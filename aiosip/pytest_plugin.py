import asyncio
import contextlib
import gc
import sys

import pytest


try:
    import uvloop
except ImportError:  # pragma: no cover
    uvloop = None


try:
    import tokio
except ImportError:  # pragma: no cover
    tokio = None


LOOP_FACTORIES = []
LOOP_FACTORY_IDS = []


def pytest_addoption(parser):
    parser.addoption(
        '--fast', action='store_true', default=False,
        help='run tests faster by disabling extra checks')
    parser.addoption(
        '--loop', action='store', default='pyloop',
        help='run tests with specific loop: pyloop, uvloop, or all')
    parser.addoption(
        '--enable-loop-debug', action='store_true', default=False,
        help='enable event loop debug mode')


@contextlib.contextmanager
def loop_context(loop_factory=asyncio.new_event_loop, fast=False):
    """A contextmanager that creates an event_loop, for test purposes.

    Handles the creation and cleanup of a test loop.
    """
    loop = setup_test_loop(loop_factory)
    yield loop
    teardown_test_loop(loop, fast=fast)


def setup_test_loop(loop_factory=asyncio.new_event_loop):
    """Create and return an asyncio.BaseEventLoop instance.

    The caller should also call teardown_test_loop, once they are done
    with the loop.
    """
    loop = loop_factory()
    asyncio.set_event_loop(loop)
    if sys.platform != "win32" and sys.version_info < (3, 12):
        # Child watchers are deprecated in 3.12 and removed in 3.14.
        policy = asyncio.get_event_loop_policy()
        watcher = asyncio.SafeChildWatcher()
        watcher.attach_loop(loop)
        policy.set_child_watcher(watcher)
    return loop


def teardown_test_loop(loop, fast=False):
    """Teardown and cleanup an event_loop created by setup_test_loop."""
    closed = loop.is_closed()
    if not closed:
        loop.call_soon(loop.stop)
        loop.run_forever()
        loop.close()

    if not fast:
        gc.collect()

    asyncio.set_event_loop(None)


def pytest_configure(config):
    loops = config.getoption('--loop')

    factories = {'pyloop': asyncio.new_event_loop}

    if uvloop is not None:  # pragma: no cover
        factories['uvloop'] = uvloop.new_event_loop

    if tokio is not None:  # pragma: no cover
        factories['tokio'] = tokio.new_event_loop

    if loops == 'all':
        loops = 'pyloop,uvloop?,tokio?'

    selected = []
    for name in loops.split(','):
        required = not name.endswith('?')
        name = name.strip(' ?')
        if name in factories:
            selected.append((name, factories[name]))
        elif required:
            # A bad --loop value is a user error; ValueError here surfaces as
            # pytest's INTERNALERROR traceback instead of a usage message.
            raise pytest.UsageError(
                "Unknown loop '%s', available loops: %s" % (
                    name, list(factories.keys())))

    if not selected:
        raise pytest.UsageError(
            "--loop %r selected no available event loop" % config.getoption('--loop'))

    config._aiosip_loops = selected
    # Kept in sync for anything still reading the module level lists.
    LOOP_FACTORY_IDS[:] = [name for name, _ in selected]
    LOOP_FACTORIES[:] = [factory for _, factory in selected]
    asyncio.set_event_loop(None)


def pytest_pycollect_makeitem(collector, name, obj):
    """Fix pytest collecting for coroutines."""
    if collector.funcnamefilter(name) and asyncio.iscoroutinefunction(obj):
        return list(collector._genfunctions(name, obj))


def pytest_pyfunc_call(pyfuncitem):
    """Run coroutines in an event loop instead of a normal function call."""
    if asyncio.iscoroutinefunction(pyfuncitem.function):
        testargs = {arg: pyfuncitem.funcargs[arg]
                    for arg in pyfuncitem._fixtureinfo.argnames}

        _loop = pyfuncitem.funcargs.get('loop', None)
        task = _loop.create_task(pyfuncitem.obj(**testargs))
        _loop.run_until_complete(task)

        return True


def pytest_generate_tests(metafunc):
    """Parametrize the ``loop`` fixture with the loops selected by ``--loop``.

    The selection is only known in pytest_configure, which is too late for a
    ``params=`` argument on the fixture decorator (evaluated at import time),
    so the parametrization happens here, at collection time. Tests and
    downstream conftests that parametrize ``loop`` themselves are left alone.

    NOTE: the override detection reads private pytest surfaces
    (``metafunc._arg2fixturedefs`` and a FixtureDef's ``func``), and the loop
    selection is read from ``config._aiosip_loops`` stashed by
    ``pytest_configure``. Verified against pytest 8.2.2 (CPython 3.9) and
    pytest 9.0.2 (CPython 3.12); re-check these three when bumping pytest.
    """
    if 'loop' not in metafunc.fixturenames:
        return

    fixturedefs = metafunc._arg2fixturedefs.get('loop')
    if not fixturedefs or getattr(fixturedefs[-1].func, '__module__', None) != __name__:
        return  # a downstream conftest provides its own loop fixture

    for marker in metafunc.definition.iter_markers('parametrize'):
        argnames = marker.args[0] if marker.args else marker.kwargs.get('argnames', '')
        if isinstance(argnames, str):
            argnames = [name.strip() for name in argnames.split(',')]
        if 'loop' in argnames:
            return

    loops = metafunc.config._aiosip_loops
    metafunc.parametrize('loop', [factory for _, factory in loops],
                         ids=[name for name, _ in loops], indirect=True)


@pytest.fixture
def loop(request):
    """Return an instance of the event loop selected by ``--loop``."""
    loop_factory = request.param
    fast = request.config.getoption('--fast')
    debug = request.config.getoption('--enable-loop-debug')

    with loop_context(loop_factory, fast=fast) as _loop:
        if debug:
            _loop.set_debug(True)  # pragma: no cover
        yield _loop
