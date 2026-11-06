import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {webcrypto} from 'node:crypto';
const source=await readFile(new URL('../../../assets/restore-passkey-export.js',import.meta.url),'utf8');
const {publicCandidate,mount}=await import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`);
const b64=b=>Buffer.from(b).toString('base64url');
const x=Buffer.from('60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6','hex');
const y=Buffer.from('7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299','hex');
const key=await webcrypto.subtle.importKey('jwk',{kty:'EC',crv:'P-256',x:b64(x),y:b64(y)}, {name:'ECDSA',namedCurve:'P-256'},true,['verify']);
const spki=new Uint8Array(await webcrypto.subtle.exportKey('spki',key));
const cose=new Uint8Array([0xa5,1,2,3,0x26,0x20,1,0x21,0x58,0x20,...x,0x22,0x58,0x20,...y]);
const saved={email:'álîce@example.org',subject:'opaque-主体',origin:'https://security.example.test',handle:new Uint8Array(32).fill(7),challenge:new Uint8Array(32).fill(9)};

async function fixture(context=saved){
  const id=new Uint8Array([11,22,33]);
  const auth=new Uint8Array(55+id.length+cose.length);
  auth.set(new Uint8Array(await webcrypto.subtle.digest('SHA-256',new TextEncoder().encode('security.example.test'))));
  auth[32]=0x4d;auth[54]=id.length;auth.set(id,55);auth.set(cose,55+id.length);
  const client={type:'webauthn.create',challenge:b64(context.challenge),origin:context.origin,crossOrigin:false};
  const credential={type:'public-key',rawId:id,response:{getPublicKeyAlgorithm:()=>-7,getAuthenticatorData:()=>auth,
    getPublicKey:()=>spki,clientDataJSON:new TextEncoder().encode(JSON.stringify(client))}};
  return {credential,auth,client,context};
}

test('exports actual checked COSE, user handle and BE; never SPKI or private fields',async()=>{
  const f=await fixture();f.credential.privateKey='PRIVATE-FIXTURE';
  const record=await publicCandidate(f.credential,saved,webcrypto);
  assert.deepEqual(record,{email:saved.email,subject:saved.subject,credential_id:[11,22,33],user_handle:Array.from(saved.handle),
    cose_key:Array.from(cose),backup_eligible:true,rp_id:'security.example.test',origin:saved.origin});
  assert.notDeepEqual(record.cose_key,Array.from(spki));
  assert.ok(!JSON.stringify(record).includes('PRIVATE-FIXTURE'));
  f.auth[32]=0x45;assert.equal((await publicCandidate(f.credential,saved,webcrypto)).backup_eligible,false);
});

for (const mutation of ['uv','up','at','reserved','extension','backup','id','rp','cose-private','cose-duplicate','spki-as-cose','point','algorithm','client-type','origin','challenge','cross-origin','trailing']) {
  test(`refuses changed actual registration ${mutation}`,async()=>{
    const f=await fixture();
    switch(mutation){
      case 'uv':f.auth[32]&=~4;break;case 'up':f.auth[32]&=~1;break;case 'at':f.auth[32]&=~0x40;break;
      case 'reserved':f.auth[32]|=2;break;case 'extension':f.auth[32]|=0x80;break;case 'backup':f.auth[32]=0x55;break;
      case 'id':f.credential.rawId=new Uint8Array([11,22,34]);break;case 'rp':f.auth[0]^=1;break;
      case 'cose-private':f.auth[55+3+7]=0x23;break;case 'cose-duplicate':f.auth[55+3+42]=0x21;break;
      case 'spki-as-cose':f.credential.response.getAuthenticatorData=()=>new Uint8Array([...f.auth.slice(0,58),...spki]);break;
      case 'point':f.auth[55+3+10]^=1;break;case 'algorithm':f.credential.response.getPublicKeyAlgorithm=()=>-8;break;
      case 'client-type':f.client.type='webauthn.get';break;case 'origin':f.client.origin='https://other.example.test';break;
      case 'challenge':f.client.challenge=b64(new Uint8Array(32));break;case 'cross-origin':f.client.crossOrigin=true;break;
      case 'trailing':f.credential.response.getAuthenticatorData=()=>new Uint8Array([...f.auth,0]);break;
    }
    f.credential.response.clientDataJSON=new TextEncoder().encode(JSON.stringify(f.client));
    await assert.rejects(publicCandidate(f.credential,saved,webcrypto));
  });
}

function page(){
  const root={dataset:{origin:saved.origin,email:saved.email,subject:saved.subject},isConnected:true};
  const button={disabled:false,addEventListener:(type,fn)=>{assert.equal(type,'click');button.click=fn;}};
  const output={value:'old'},status={textContent:''};
  const nodes=new Map([['restore-passkey-export',root],['create-passkey',button],['public-key-record',output],['passkey-status',status]]);
  const document={getElementById:id=>nodes.get(id)};
  const window={isSecureContext:true,location:{origin:saved.origin}};window.top=window;window.self=window;
  return {root,button,output,status,document,window};
}

test('requires real browser create UV and freezes exact request handle; double clicks cannot replace it',async()=>{
  const p=page();let calls=0,release,actualHandle;
  const navigator={credentials:{create:async options=>{
    calls++;actualHandle=Array.from(options.publicKey.user.id);assert.equal(options.publicKey.authenticatorSelection.userVerification,'required');
    assert.equal(options.publicKey.authenticatorSelection.residentKey,'required');
    assert.deepEqual(options.publicKey.pubKeyCredParams,[{type:'public-key',alg:-7}]);
    await new Promise(resolve=>{release=resolve;});
    const f=await fixture({...saved,challenge:options.publicKey.challenge,handle:options.publicKey.user.id});
    return f.credential;
  }}};
  mount(p.document,p.window,navigator,webcrypto);
  const first=p.button.click();await p.button.click();assert.equal(calls,1);release();await first;
  const record=JSON.parse(p.output.value);assert.equal(record.user_handle.length,32);
  assert.deepEqual(record.user_handle,actualHandle);
  assert.notDeepEqual(record.user_handle,Array.from(new TextEncoder().encode(saved.email)));
  assert.match(p.status.textContent,/reviewed configuration change/);
});

test('no export after a DOM identity change or foreign failure, and no failure detail is displayed',async()=>{
  for(const kind of ['changed','error','iframe','http']){
    const p=page();let calls=0;
    const navigator={credentials:{create:async options=>{
      calls++;if(kind==='error')throw new Error('PRIVATE-FIXTURE');
      const f=await fixture({...saved,challenge:options.publicKey.challenge});
      p.root.dataset.subject='replacement';return f.credential;
    }}};
    if(kind==='iframe')p.window.top={};if(kind==='http')p.window.isSecureContext=false;
    mount(p.document,p.window,navigator,webcrypto);await p.button.click();
    assert.equal(p.output.value,'');assert.ok(!p.status.textContent.includes('PRIVATE-FIXTURE'));
    if(['iframe','http'].includes(kind))assert.equal(calls,0);
    assert.equal(p.button.disabled,false);
  }
});
