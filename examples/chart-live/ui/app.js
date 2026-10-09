import './clanker-ui.js';
import {installChartNavigation} from './chart-navigation.js';

function install() {
  installChartNavigation({
    document, view: window, location, history,
    fetch: window.fetch.bind(window),
    parseHTML: source => new DOMParser().parseFromString(source, 'text/html'),
    createAbortController: () => new AbortController(),
    schedule: (callback, delay) => window.setTimeout(callback, delay),
    cancelSchedule: token => window.clearTimeout(token)
  });
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', install, {once: true});
} else {
  install();
}
