// App-owned range selection and dialogs; Native owns navigation and live streams.
import {canonicalPageURL, createPageNavigation} from '/assets/platform/navigation.js';

export function responseRange(document, start, end) {
  const region = document.getElementById('chart-region');
  const revisions = document.getElementById('sample-revisions');
  if (!region || !revisions || region.dataset.start !== String(start) || region.dataset.end !== String(end)) return null;
  return [region, revisions];
}
export function rangeTarget(raw, base, defaultStart, defaultEnd, origin) {
  const route = canonicalPageURL(raw, base, {start: defaultStart, end: defaultEnd}, origin);
  if (!route || !/^-?\d+$/.test(route.values.start) || !/^\d+$/.test(route.values.end)) return null;
  const start = Number(route.values.start), end = Number(route.values.end);
  if (![start, end, defaultStart, defaultEnd].every(Number.isSafeInteger) || start >= end) return null;
  // Canonicalize accepted integer spelling before the platform serializes it.
  const input = new URL(route.url); input.search = '';
  input.searchParams.set('start', String(start)); input.searchParams.set('end', String(end));
  return {...canonicalPageURL(input, base, {start: defaultStart, end: defaultEnd}, origin), start, end};
}
export function installChartNavigation(ports) {
  const {document, view, location} = ports;
  const form = document.getElementById('chart-range'), status = document.getElementById('chart-request-status');
  const dialog = document.getElementById('sample-dialog'), values = document.getElementById('sample-dialog-values');
  if (!form || !status || !dialog || !values) return () => {};
  const listeners = []; let stopped = false;
  function listen(node, name, fn, options) { node.addEventListener(name, fn, options); listeners.push(() => node.removeEventListener(name, fn, options)); }
  function closeDialog() { if (dialog.open) dialog.close(); values.textContent = ''; }
  const navigation = createPageNavigation({
    ...ports,
    target: raw => rangeTarget(raw, form.action, Number(form.dataset.defaultStart), Number(form.dataset.defaultEnd), location.origin),
    accept: (parsed, next) => responseRange(parsed, next.start, next.end),
    pending() { status.textContent = 'Loading current data for the selected range…'; },
    accepted(next) {
      closeDialog(); form.elements.start.value = String(next.start); form.elements.end.value = String(next.end);
      status.textContent = 'Selected range confirmed by the server. Current persisted data is shown.';
    },
    failed(timedOut) { status.textContent = timedOut ? 'Range request cancelled or timed out. The current chart is retained.' : 'The range could not be loaded. The current chart and drafts are retained. Retry Apply range.'; },
    cancelled() { status.textContent = 'Range change cancelled. The current chart is retained.'; }
  });
  const {navigate, cancel} = navigation;
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
  function stop() {
    if (stopped) return;
    stopped = true; navigation.stop(); closeDialog();
    for (const off of listeners.reverse()) off();
  }
  listen(view, 'pagehide', event => { if (!event.persisted) stop(); });
  return stop;
}
