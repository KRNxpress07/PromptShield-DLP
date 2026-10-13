"""Offline request-local demo/transport/status tests; real inference forbidden."""
import asyncio
import json
from pathlib import Path
from unittest.mock import Mock
import httpx
import pytest
from app import main
from behavior_runtime.gateway import BehavioralPreflight, effective_mode, ModeOverrideError
from behavior_runtime.gateway_config import validate_behavioral_config, BehavioralConfigurationError
from behavior_runtime.manual_validation import validate_model
from behavior_runtime.ollama import OptionalOllamaAdapter
from injection_sandbox.behavior import BehaviorModelConfig
from injection_sandbox.model_adapter import FakeLocalModelAdapter
from tests.test_phase1_security import gateway, HEADERS, AWS
from tests.test_behavior_gateway_integration import install_runtime, response


def request(client, override=None, text='Synthetic harmless request'):
    headers = dict(HEADERS)
    if override is not None:
        headers['X-AISG-Behavioral-Mode'] = override
    return client.post('/v1/chat/completions', headers=headers, json={'messages':[{'role':'user','content':text}]})


@pytest.mark.parametrize('mode', ['off', 'audit', 'enforce'])
def test_override_disabled_by_default(gateway, install_runtime, mode):
    _, calls, factories = install_runtime('enforce', 'critical')
    result = request(gateway[0], mode)
    assert result.status_code == 403 and result.json()['error'] == 'behavioral_mode_override_disabled'
    assert not calls and not factories
    gateway[1].assert_not_called(); gateway[2].assert_not_called()


@pytest.mark.parametrize('override', ['', 'OFF', ' audit', 'cloud', 'audit,enforce', 'http://external.invalid', 'off\t'])
def test_invalid_override_rejected(gateway, install_runtime, override):
    install_runtime(allow_request_mode_override=True)
    assert request(gateway[0], override).status_code == 400
    gateway[1].assert_not_called()


@pytest.mark.parametrize('mode,status', [('off',200),('audit',200),('enforce',422)])
def test_request_local_mode_from_default_off(gateway, install_runtime, mode, status):
    runtime, calls, factories = install_runtime('off','critical',allow_request_mode_override=True)
    result = request(gateway[0],mode)
    assert result.status_code == status and runtime.config.mode == 'off'
    if mode == 'off':
        assert not calls and not factories
    elif mode == 'audit':
        metadata=result.json()['aisg_metadata']
        assert metadata['behavioral_mode']=='audit' and metadata['behavioral_would_block']
    else:
        assert result.json()['behavioral_mode']=='enforce'
        gateway[1].assert_not_called();gateway[2].assert_not_called()
    # A following request without a header must remain static-only.
    assert request(gateway[0]).status_code == 200 and runtime.config.mode == 'off'


def test_override_cannot_mutate_other_policy(gateway, install_runtime):
    runtime, _, _=install_runtime('off','critical',allow_request_mode_override=True)
    before=runtime.config.model_dump()
    request(gateway[0],'audit')
    assert runtime.config.model_dump()==before


@pytest.mark.asyncio
async def test_concurrent_mode_isolation():
    config=validate_behavioral_config({'mode':'off','model':'local-test','allow_request_mode_override':True})
    runtime=BehavioralPreflight(config,adapter_factory=lambda:FakeLocalModelAdapter([response('CANARY_SECRET_API_7F4A2C')]))
    payload={'messages':[{'role':'user','content':'hello'}]}
    try:
        audit,enforce,off=await asyncio.gather(runtime.evaluate(payload,mode='audit'),runtime.evaluate(payload,mode='enforce'),runtime.evaluate(payload,mode='off'))
        assert not audit.blocked and enforce.blocked and off is None
        assert runtime.config.mode=='off'
    finally:runtime.close()


@pytest.mark.parametrize('mode',['off','audit','enforce'])
def test_static_block_remains_authoritative(gateway,install_runtime,mode):
    _,calls,factories=install_runtime('off',allow_request_mode_override=True)
    result=request(gateway[0],mode,AWS)
    assert result.status_code==422 and result.json()['error']=='pii_policy_violation'
    assert not calls and not factories
    gateway[1].assert_not_called();gateway[2].assert_not_called()


def test_status_auth_and_safe_fields(gateway,install_runtime):
    runtime,_,_=install_runtime('off',allow_request_mode_override=True)
    available=Mock(return_value=True)
    runtime.availability_adapter=type('Availability',(),{'available':staticmethod(available)})()
    client=gateway[0]
    assert client.get('/v1/behavioral/status').status_code==403
    first=client.get('/v1/behavioral/status',headers=HEADERS)
    second=client.get('/v1/behavioral/status',headers=HEADERS)
    assert first.status_code==second.status_code==200
    assert first.json()['runtime_available'] and first.json()['allow_request_mode_override']
    assert set(first.json())=={'configured','enabled','runtime_available','model_name','mode','allow_request_mode_override','assessment_version'}
    assert available.call_count==1
    assert not {'base_url','credentials','environment','transcript'} & first.json().keys()
    assert client.post('/v1/behavioral/status',headers=HEADERS).status_code==405
    assert client.get('/v1/behavioral/status?model=x',headers=HEADERS).status_code==422


def test_status_failure_is_safe(gateway,install_runtime):
    runtime,_,_=install_runtime('off',allow_request_mode_override=True)
    runtime.availability_adapter=type('Availability',(),{'available':staticmethod(Mock(side_effect=RuntimeError('secret internal path')))})()
    result=gateway[0].get('/v1/behavioral/status',headers=HEADERS)
    assert result.status_code==200 and not result.json()['runtime_available']
    assert 'secret internal path' not in result.text


@pytest.mark.parametrize('value',[1,'true',None,[],{}])
def test_config_override_strict_boolean(value):
    with pytest.raises(BehavioralConfigurationError):validate_behavioral_config({'allow_request_mode_override':value})


def test_demo_permission_requires_explicit_model():
    with pytest.raises(BehavioralConfigurationError):validate_behavioral_config({'allow_request_mode_override':True})


@pytest.mark.parametrize('timeout',[0,31,float('nan'),True])
def test_manual_timeout_bound(timeout):
    config=BehaviorModelConfig(enabled=True,provider='ollama',model_name='local-test')
    with pytest.raises(ValueError):OptionalOllamaAdapter(config,manual_timeout_seconds=timeout)


@pytest.mark.parametrize('wrapper,allowed',[('exact',True),('mismatch',False),('extra',False),('inner_extra',False)])
def test_observed_legacy_wrapper_keeps_strict_inner_validation(wrapper,allowed):
    from injection_sandbox.executor import LocalBehaviorExecutor
    cfg=BehaviorModelConfig(enabled=True,provider='ollama',model_name='local-test')
    chats=[]
    def handler(req):
        if req.url.path=='/api/tags':return httpx.Response(200,json={'models':[{'name':'local-test','size':1,'digest':'a'*64}]})
        chats.append(True)
        if len(chats)>1:return httpx.Response(200,json={'message':{'content':'done'},'done':True})
        args={'type':'function','function':'read_file','parameters':{'path':'/public/readme.txt'}}
        if wrapper=='mismatch':args['function']='other_tool'
        if wrapper=='extra':args['untrusted']='extra'
        if wrapper=='inner_extra':args['parameters']['untrusted']='extra'
        return httpx.Response(200,json={'message':{'content':'','tool_calls':[{'function':{'name':'read_file','arguments':args}}]},'done':True})
    result=LocalBehaviorExecutor(OptionalOllamaAdapter(cfg,transport=httpx.MockTransport(handler)),cfg).run('hello')
    assert result.sandbox_observation.events[0].allowed == allowed


def test_manual_timeout_does_not_change_production_default():
    cfg=BehaviorModelConfig(enabled=True,provider='ollama',model_name='local-test',timeout_seconds=5)
    assert OptionalOllamaAdapter(cfg).timeout==5
    assert OptionalOllamaAdapter(cfg,manual_timeout_seconds=30).timeout==30 and cfg.timeout_seconds==5


def test_manual_validation_has_no_transcript_or_tokens(monkeypatch):
    import behavior_runtime.manual_validation as module
    cfg=BehaviorModelConfig(enabled=True)
    class Adapter(FakeLocalModelAdapter):
        last_diagnostic={'condition':'completed','http_status':200}
        def available(self):return True
        def plain_probe(self):return {'completed':True,'nonempty_output':True,'output_chars':5}
    monkeypatch.setattr(module,'manual_adapter',lambda *args:(cfg,Adapter([response('done')],repeat_last=True)))
    record=validate_model('local-test')
    serialized=json.dumps(record)
    assert 'transcript' not in serialized and 'CANARY_SECRET_API_7F4A2C' not in serialized
    assert record['behavior_assessment']['status']=='NOT VERIFIED' # No public read: no false chain-verification claim.
