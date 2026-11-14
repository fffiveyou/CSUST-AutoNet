"""Shared system-proxy contract across clients, without host registry writes."""
import pytest

from proxy.base import ProxyOperationError, create_proxy_adapter, proxy_catalog
from system.proxy_settings import RegistryValue, WindowsSystemProxy
from test_phase2 import FakeRegistry, manual_proxy_values

CLIENTS = [key for key, _, supported in proxy_catalog() if supported and key != 'none']


@pytest.mark.parametrize('key', CLIENTS)
@pytest.mark.parametrize('mode', ['manual', 'pac', 'disabled', 'missing'])
@pytest.mark.parametrize('failure', [False, True])
def test_client_restores_exact_snapshot(key, mode, failure):
    values = manual_proxy_values() if mode == 'manual' else {}
    if mode == 'pac':
        values = {'AutoConfigURL': RegistryValue(True, 'http://localhost/test.pac', 1)}
    elif mode == 'disabled':
        values = {'ProxyEnable': RegistryValue(True, 0, 4)}
    backend = FakeRegistry(values)
    proxy = WindowsSystemProxy(backend)
    original = proxy.capture()
    adapter = create_proxy_adapter(key, system_proxy=proxy, dry_run=False)
    def forbidden():
        raise AssertionError('Authentication must not enumerate/control processes')
    adapter._running_paths = forbidden
    try:
        with adapter.authentication_bypass():
            assert not proxy.is_active()
            if failure:
                raise RuntimeError('offline failure')
    except RuntimeError:
        assert failure
    assert proxy.capture() == original


@pytest.mark.parametrize('key', CLIENTS)
def test_factory_dry_run_and_executable_discovery(key, tmp_path, monkeypatch):
    backend = FakeRegistry(manual_proxy_values())
    adapter = create_proxy_adapter(key, system_proxy=WindowsSystemProxy(backend))
    with adapter.authentication_bypass():
        pass
    assert not backend.writes and not backend.deletes
    exe = tmp_path / sorted(adapter.PROCESS_NAMES)[0]
    exe.touch()
    configured = create_proxy_adapter(key, exe_path=str(exe), system_proxy=WindowsSystemProxy(backend))
    assert configured.locate_executable() == exe
    class Process:
        info = {'name': exe.name.upper(), 'exe': str(exe)}
    monkeypatch.setattr('proxy.windows_system.psutil.process_iter', lambda fields: [Process()])
    assert adapter.is_application_running()
    assert adapter.locate_executable() == exe


@pytest.mark.parametrize('key', CLIENTS)
def test_partial_prepare_failure_rolls_back_without_login(key):
    class FailOnce(FakeRegistry):
        failed = False
        def delete(self, name):
            if name == 'AutoConfigURL' and not self.failed:
                self.failed = True
                raise OSError('simulated registry failure')
            super().delete(name)
    backend = FailOnce(manual_proxy_values())
    proxy = WindowsSystemProxy(backend)
    snapshot = proxy.capture()
    adapter = create_proxy_adapter(key, system_proxy=proxy, dry_run=False)
    with pytest.raises(ProxyOperationError, match='已恢复原设置'):
        with adapter.authentication_bypass():
            pytest.fail('must not authenticate after partial disable failure')
    assert proxy.capture() == snapshot
