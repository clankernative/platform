// App-owned view navigation and dialogs. No chart engine or component-owned query.
export function navigationState(acceptedURL) {
  let generation=0, accepted=acceptedURL;
  return Object.freeze({
    begin(){if(generation>=1000000)throw new Error('navigation_budget');return ++generation;},
    current(token){return token===generation;},
    accept(token,url){if(token!==generation)return false;accepted=url;return true;},
    cancel(){if(generation>=1000000)throw new Error('navigation_budget');++generation;},
    accepted(){return accepted;}
  });
}
export function responseRange(document,start,end) {
  const region=document.getElementById('chart-region');
  const revisions=document.getElementById('sample-revisions');
  const live=document.getElementById('day2-live');
  if (!region?.hasAttribute('data-live') || !revisions?.hasAttribute('data-live') || !live ||
      region.dataset.start!==String(start) || region.dataset.end!==String(end) ||
      region.querySelector('form,input,textarea,select,script') || revisions.querySelector('form,input,textarea,select,script')) return null;
  return {region,revisions,live};
}
export function rangeTarget(raw,base,defaultStart,defaultEnd,origin) {
  let url,page;
  try { url=new URL(raw,base);page=new URL(base); } catch { return null; }
  if(url.origin!==origin||url.pathname!==page.pathname)return null;
  const keys=[...url.searchParams.keys()];
  if(keys.length>2||new Set(keys).size!==keys.length||keys.some(key=>key!=='start'&&key!=='end'))return null;
  const startText=url.searchParams.get('start')??String(defaultStart),endText=url.searchParams.get('end')??String(defaultEnd);
  if(!/^-?\d+$/.test(startText)||!/^\d+$/.test(endText))return null;
  const start=Number(startText),end=Number(endText);
  if(![start,end,defaultStart,defaultEnd].every(Number.isSafeInteger)||start>=end)return null;
  // Native's named route serializer orders fields and omits declared defaults.
  url.search='';url.hash='';
  if(end!==defaultEnd)url.searchParams.set('end',String(end));
  if(start!==defaultStart)url.searchParams.set('start',String(start));
  return {url,start,end};
}
export function installChartNavigation({document, view, location, history, fetch, parseHTML, createAbortController, schedule, cancelSchedule}) {
  const form=document.getElementById('chart-range'), status=document.getElementById('chart-request-status');
  const dialog=document.getElementById('sample-dialog'), values=document.getElementById('sample-dialog-values');
  if(!form||!status||!dialog||!values)return () => {};
  const state=navigationState(location.href);let request=null, stopped=false;
  const timers=new Set();
  const listeners=[];
  function listen(node,name,fn,options){node.addEventListener(name,fn,options);listeners.push(()=>node.removeEventListener(name,fn,options));}
  function closeDialog(){if(dialog.open)dialog.close();values.textContent='';}
  function cancel(){state.cancel();request?.abort();request=null;status.textContent='Range change cancelled. The current chart is retained.';}
  function target(raw) {
    return rangeTarget(raw,form.action,Number(form.dataset.defaultStart),Number(form.dataset.defaultEnd),location.origin);
    // Roc owns bounds, authorization and accepted data.
  }
  async function navigate(raw,historyMode='push') {
    const next=target(raw);if(!next){status.textContent='Choose a valid range. The current chart is retained.';return;}
    const token=state.begin();request?.abort();const controller=createAbortController();request=controller;
    const timeout=schedule(()=>controller.abort(),12000);timers.add(timeout);
    status.textContent='Loading current data for the selected range…';
    const previousLive=document.getElementById('day2-live');let removedLive=false;
    try{
      const response=await fetch(next.url,{credentials:'same-origin',signal:controller.signal,redirect:'error',headers:{Accept:'text/html'}});
      if(!state.current(token)||stopped)return;
      if(!response.ok||!response.headers.get('content-type')?.includes('text/html'))throw new Error('range_response');
      const source=await response.text();
      if(!state.current(token)||stopped||controller.signal.aborted)return;
      if(source.length>1048576)throw new Error('range_budget');
      const parsed=parseHTML(source);
      const checked=responseRange(parsed,next.start,next.end);if(!checked)throw new Error('range_identity');
      const liveURL=new URL(checked.live.dataset.liveUrl,location.origin);
      if(liveURL.origin!==location.origin||liveURL.pathname!=='/_live'||liveURL.searchParams.get('path')!==next.url.pathname+next.url.search)throw new Error('live_identity');
      const region=document.getElementById('chart-region'), revisions=document.getElementById('sample-revisions');
      if(!region?.isConnected||!revisions?.isConnected||!previousLive?.isConnected)throw new Error('range_root');
      // The initializer is host-produced. Never synthesize Datastar expressions.
      // Disconnect and flush cleanup first so the old range's stream is aborted
      // before inserting the new chart. Commands/drafts are not replaced.
      previousLive.remove();removedLive=true;await Promise.resolve();
      if(!state.current(token)||stopped||controller.signal.aborted){if(!stopped&&!document.getElementById('day2-live'))document.body.prepend(previousLive.cloneNode(true));removedLive=false;return;}
      closeDialog();region.replaceWith(document.importNode(checked.region,true));revisions.replaceWith(document.importNode(checked.revisions,true));
      document.body.prepend(document.importNode(checked.live,true));removedLive=false;
      if(!state.accept(token,next.url.href))return;
      if(historyMode==='push')history.pushState(null,'',next.url);else history.replaceState(null,'',next.url);
      form.elements.start.value=String(next.start);form.elements.end.value=String(next.end);
      status.textContent='Selected range confirmed by the server. Current persisted data is shown.';
    }catch(error){
      if(removedLive&&previousLive&&!stopped&&!document.getElementById('day2-live'))document.body.prepend(previousLive.cloneNode(true));
      if(state.current(token)&&!stopped){
        if(historyMode==='replace')history.replaceState(null,'',state.accepted());
        status.textContent=controller.signal.aborted?'Range request cancelled or timed out. The current chart is retained.':'The range could not be loaded. The current chart and drafts are retained. Retry Apply range.';
      }
    }finally{cancelSchedule(timeout);timers.delete(timeout);if(state.current(token))request=null;}
  }
  listen(form,'submit',event=>{
    if(!form.reportValidity())return;event.preventDefault();const url=new URL(form.action,location.href);
    url.search='';url.searchParams.set('start',form.elements.start.value);url.searchParams.set('end',form.elements.end.value);void navigate(url);
  });
  listen(document,'click',event=>{
    const link=event.target.closest?.('a[data-chart-navigation]');
    if(!link||event.button!==0||event.metaKey||event.ctrlKey||event.shiftKey||event.altKey)return;
    event.preventDefault();void navigate(link.href);
  });
  listen(document,'cui-chart:range-committed',event=>{
    if(event.target.id!=='sample-chart')return;const {start,end}=event.detail??{};
    if(!Number.isSafeInteger(start)||!Number.isSafeInteger(end))return;
    const url=new URL(form.action,location.href);url.search='';url.searchParams.set('start',String(start));url.searchParams.set('end',String(end));void navigate(url);
  });
  listen(document,'cui-chart:range-cancelled',event=>{if(event.target.id==='sample-chart')cancel();});
  listen(document,'cui-chart:point-activated',event=>{
    if(event.target.id!=='sample-chart')return;const {key,time,value,missing}=event.detail??{};
    if(typeof key!=='string'||!key||key.length>80||!Number.isSafeInteger(time)||Math.abs(time)>8640000000000000||!Number.isSafeInteger(value)||typeof missing!=='boolean')return;
    values.textContent=`${new Date(time).toISOString()} · ${missing?'Missing sample':`Value ${value}`} · Record ${key}`;
    if(!dialog.open)dialog.showModal();
  });
  listen(document,'cui-chart:unmounted',event=>{if(event.detail?.chartId==='sample-chart')closeDialog();});
  listen(document.getElementById('sample-dialog-close'),'click',closeDialog);
  listen(view,'popstate',()=>{void navigate(location.href,'replace');});
  function stop(){if(stopped)return;stopped=true;state.cancel();request?.abort();for(const timer of timers)cancelSchedule(timer);timers.clear();closeDialog();for(const off of listeners.reverse())off();}
  listen(view,'pagehide',event=>{if(!event.persisted)stop();else cancel();});
  return stop;
}
