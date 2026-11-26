// Exercises Rust-rendered documents, Chromium's actual CSP/iframe enforcement
// and document replacement. All endpoints and data are synthetic and loopback.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";

const fixture = JSON.parse(await readFile(process.argv[2], "utf8"));
const profile = await mkdtemp(join(tmpdir(), "day2-prototype-chrome-"));
const requests = [];
const listen = server => new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
const origin = server => "http://127.0.0.1:" + server.address().port;
const trap = createServer((request, response) => { requests.push("trap" + request.url); response.end(); });
await listen(trap);

const probe = `
const report = (kind, value) => parent.postMessage({kind,value}, "*");
addEventListener("message", async event => {
    if (event.source !== parent) return;
    if (event.data === "read") {
        try {
            const result = await day2.call("history");
            report("result", {messages:result.messages, ids:result.ids.map(id => [typeof id, String(id)])});
        }
        catch (error) { report("error", error.message); }
    }
    if (event.data === "navigate") location.href = ${JSON.stringify(origin(trap) + "/navigation")};
});
(async () => {
    let cookieBlocked = false, parentBlocked = false, fetchBlocked = false;
    try { void document.cookie; } catch { cookieBlocked = true; }
    try { void parent.document.body; } catch { parentBlocked = true; }
    try { await fetch(${JSON.stringify(origin(trap) + "/fetch")}); } catch { fetchBlocked = true; }
    const image = new Image(); image.src = ${JSON.stringify(origin(trap) + "/image")};
    const denied = await Promise.all([
        day2.call("other").then(() => false, () => true),
        day2.call("history", {}).then(() => false, () => true)
    ]);
    report("ready", {cookieBlocked, parentBlocked, fetchBlocked, denied});
})();`;
const handshake = `const channel = new MessageChannel();
parent.postMessage("day2.prototype.connect.v1", "*", [channel.port2]);
channel.port1.onmessage = event => parent.postMessage({kind:"unexpected", value:event.data}, "*");
channel.port1.postMessage({id:1, operation:"history"});
parent.postMessage({kind:"attempted"}, "*");`;

let releaseFrame, pendingRead;
const firstFrame = new Promise(resolve => { releaseFrame = resolve; });
let mode = "allow";
const saves = [];
const invocation = "api-command-fixture";
const statusPath = "/api/invocations/" + invocation;
let settled = false, polls = 0;
const server = createServer(async (req, res) => {
    requests.push(req.url);
    res.setHeader("Cache-Control", "no-store");
    if (["/", "/editor", "/frame?pin=one"].includes(req.url)) {
        const isFrame = req.url === "/frame?pin=one";
        if (isFrame) await firstFrame;
        const [body, policy] = isFrame ? fixture.frame : (req.url === "/editor" ? fixture.editor : fixture.shell);
        res.setHeader("Content-Type", "text/html; charset=utf-8");
        res.setHeader("Content-Security-Policy", policy);
        res.end(isFrame ? body.replace("/* TEST_PROBE */", () => probe) : body);
    } else if (req.url === "/query?pin=one") {
        assert.equal(req.headers["x-day2-prototype-query"], "1");
        assert.equal(req.headers["sec-fetch-site"], "same-origin");
        assert.equal(req.headers["sec-fetch-dest"], "empty");
        assert.equal(req.headers["sec-fetch-mode"], "same-origin");
        res.setHeader("Content-Type", "application/json");
        if (mode === "delay") await new Promise(resolve => { pendingRead = resolve; });
        res.statusCode = mode === "deny" ? 403 : 200;
        res.end('{"messages":[{"text":"fixture"}],"ids":[42,9007199254740993,18446744073709551615,-9223372036854775808]}');
    } else if (req.url === "/api/session") {
        res.setHeader("Content-Type", "application/json"); res.end('{"csrf_token":"fixture-token"}');
    } else if (req.url === "/api/app.save") {
        assert.equal(req.method, "POST");
        assert.equal(req.headers.origin, origin(server));
        assert.equal(req.headers["x-csrf-token"], "fixture-token");
        assert.match(req.headers["content-type"], /^application\/json/);
        let body = "";
        for await (const chunk of req) body += chunk;
        saves.push({key:req.headers["idempotency-key"], body:JSON.parse(body)});
        if (saves.length === 1) { res.writeHead(403); res.end(); }
        else if (saves.length === 2) res.end('{"id":'); // Lost/truncated receipt after commit.
        else if (saves.length === 3) {
            res.writeHead(202, {"Content-Type":"application/json", Location:statusPath, "Retry-After":"1"});
            res.end(JSON.stringify({status:"pending", invocation_id:invocation, status_url:statusPath}));
        } else { res.setHeader("Content-Type", "application/json"); res.end('{"id": 9007199254740993}'); }
    } else if (req.url === statusPath) {
        polls++;
        assert.equal(req.method, "GET");
        assert.equal(req.headers["idempotency-key"], undefined);
        res.setHeader("Content-Type", "application/json");
        res.end('{"invocation_id":"' + invocation + '","operation":"app.save","status":"' +
            (settled ? 'success","result":{"id":9007199254740993}' : 'pending","result":null') + '}');
    } else if (req.url === "/_prototype/revisions/9007199254740993") {
        res.end("<main>Saved revision</main>");
    } else { res.writeHead(404); res.end(); }
});
await listen(server);

const binary = process.env.CHROME_BINARY || (process.platform === "darwin"
    ? "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" : "chromium");
const chrome = spawn(binary, ["--headless=new", "--disable-background-networking", "--disable-extensions",
    "--no-first-run", "--no-default-browser-check", "--user-data-dir=" + profile,
    "--remote-debugging-pipe", "about:blank"], {stdio:["ignore","ignore","ignore","pipe","pipe"]});
const closed = new Promise(resolve => { chrome.once("exit", resolve); chrome.once("error", resolve); });
let next = 0, buffer = "", sessionId;
const pending = new Map();
chrome.stdio[4].setEncoding("utf8");
chrome.stdio[4].on("data", data => {
    buffer += data;
    let end;
    while ((end = buffer.indexOf("\0")) !== -1) {
        const message = JSON.parse(buffer.slice(0, end));
        buffer = buffer.slice(end + 1);
        const callback = pending.get(message.id);
        if (callback) { pending.delete(message.id); callback(message); }
    }
});
const send = (method, params = {}, session) => new Promise((resolve, reject) => {
    const id = ++next;
    const timer = setTimeout(() => reject(new Error("Timed out: " + method)), 10000);
    pending.set(id, response => {
        clearTimeout(timer);
        if (response.error) reject(new Error(response.error.message)); else resolve(response.result);
    });
    chrome.stdio[3].write(JSON.stringify({id, method, params, sessionId:session}) + "\0");
});
const evaluate = async expression => {
    const result = await send("Runtime.evaluate", {expression, awaitPromise:true, returnByValue:true}, sessionId);
    if (result.exceptionDetails) throw new Error(result.exceptionDetails.exception?.description || result.exceptionDetails.text);
    return result.result.value;
};
const pause = delay => new Promise(resolve => setTimeout(resolve, delay));
const wait = async (check, timeout = 10000) => {
    const deadline = Date.now() + timeout;
    while (!await check()) { assert(Date.now() < deadline, "Timed out: " + check); await pause(20); }
};
const readCount = () => requests.filter(path => path === "/query?pin=one").length;
const report = kind => evaluate("window.reports?.find(e=>e.kind===" + JSON.stringify(kind) + ")");
const notify = command => evaluate("document.querySelector('iframe').contentWindow.postMessage(" + JSON.stringify(command) + ", '*')");
try {
    const target = await send("Target.createTarget", {url:"about:blank"});
    ({sessionId} = await send("Target.attachToTarget", {...target, flatten:true}));
    await send("Page.enable", {}, sessionId);
    await send("Page.addScriptToEvaluateOnNewDocument", {
        source:`if (window === top) { window.reports=[]; addEventListener("message",e=>{
            if (e.data?.kind) reports.push(e.data);
        }); }`
    }, sessionId);
    await send("Page.navigate", {url:origin(server)}, sessionId);
    await wait(() => evaluate("Boolean(document.querySelector('iframe'))"));
    // A sibling opaque document must not claim the real frame's first port.
    await evaluate(`const sibling = document.createElement("iframe");
      sibling.sandbox="allow-scripts"; sibling.srcdoc=${JSON.stringify("<script>" + handshake + "</script>")};
      document.body.append(sibling);`);
    await wait(() => report("attempted"));
    releaseFrame();
    await wait(() => report("ready"));
    assert.deepEqual((await report("ready")).value, {
        cookieBlocked:true, parentBlocked:true, fetchBlocked:true, denied:[true,true]
    });
    assert.equal(readCount(), 0);
    await notify("read");
    await wait(() => report("result"));
    assert.deepEqual((await report("result")).value, {messages:[{text:"fixture"}], ids:[
        ["number","42"], ["bigint","9007199254740993"], ["bigint","18446744073709551615"],
        ["bigint","-9223372036854775808"]
    ]});
    // Emulate browsers predating reviver context. A result must fail before a
    // rounded integer can reach page code; ordinary safe numbers still parse.
    await evaluate(`window.originalParse=JSON.parse;
        JSON.parse=(text,reviver)=>originalParse(text,reviver && ((k,v)=>reviver(k,v)))`);
    await notify("read");
    await wait(() => report("error"));
    assert.match((await report("error")).value, /numeric result exactly/);
    await evaluate("JSON.parse=originalParse; window.reports=[]");
    mode = "deny";
    await notify("read");
    await wait(() => report("error"));
    assert.equal((await report("error")).value, "Access denied.");
    assert.equal(readCount(), 3);
    mode = "delay";
    await notify("read");
    await wait(() => Boolean(pendingRead));
    // First try self-navigation, then explicitly replace the document behind
    // the same WindowProxy from the test shell while an old read is in flight.
    await notify("navigate");
    await pause(100);
    await evaluate(`window.reports=[]; const originalFrame=document.querySelector("iframe");
      window.originalProxy=originalFrame.contentWindow;
      originalFrame.srcdoc=${JSON.stringify("<script>" + handshake + "</script>")};`);
    await wait(() => report("attempted"));
    pendingRead();
    await pause(200);
    assert.equal(await evaluate("window.originalProxy === document.querySelector('iframe').contentWindow"), true);
    assert.equal(readCount(), 4);
    assert.equal(await report("unexpected"), undefined);
    assert(!requests.some(path => path.startsWith("trap")), "frame sent a network request: " + requests);
    assert.equal(await evaluate("document.querySelector('#editor')"), null);
    assert(!requests.includes("/api/session"));
    await send("Page.navigate", {url:origin(server) + "/editor"}, sessionId);
    await wait(() => evaluate("Boolean(document.querySelector('#editor'))"));
    await evaluate('document.querySelector("details").open=true');
    assert.equal(await evaluate('document.querySelector("textarea").value'), "<p>draft</p>");
    await evaluate('document.querySelector("#save").click()');
    await wait(() => evaluate('document.querySelector("#save-status").textContent.includes("permission")'));
    const edited = "<h1>new</h1>";
    await evaluate('document.querySelector("textarea").value=' + JSON.stringify(edited) + '; document.querySelector("#save").click()');
    await wait(() => evaluate('document.querySelector("#save-status").textContent.includes("still here")'));
    assert.equal(await evaluate('document.querySelector("textarea").value'), edited);
    await evaluate('document.querySelector("#save").click()');
    await wait(() => evaluate('document.querySelector("#save-status")?.textContent.includes("check again")'), 15000);
    assert(polls > 0 && polls <= 8, "a pending save has a bounded poll window");
    const initialPolls = polls;
    assert.equal(await evaluate('document.querySelector("textarea").value'), edited);
    settled = true;
    await evaluate('document.querySelector("#save").click()');
    await wait(() => requests.includes("/_prototype/revisions/9007199254740993"));
    assert.equal(polls, initialPolls + 1);
    assert.equal(saves.length, 3, "checking an accepted save only polls its original receipt");
    assert.match(saves[1].key, /^[a-zA-Z0-9_-]{1,128}$/);
    assert.notEqual(saves[0].key, saves[1].key);
    assert.deepEqual(saves[1], saves[2]);
    assert.deepEqual(saves[2].body, {html:edited});
    // A synchronous receipt with the same large id follows the same pinned URL.
    await send("Page.navigate", {url:origin(server) + "/editor"}, sessionId);
    await wait(() => evaluate("Boolean(document.querySelector('#editor'))"));
    await evaluate('document.querySelector("#save").click()');
    await wait(() => requests.filter(path => path === "/_prototype/revisions/9007199254740993").length === 2);
    assert.equal(saves.length, 4);
    console.log("Chromium passed frame isolation, exact integer delivery, and pending/synchronous editor retry checks.");
} finally {
    releaseFrame(); pendingRead?.();
    chrome.kill(); await closed;
    server.closeAllConnections(); trap.closeAllConnections(); server.close(); trap.close();
    await rm(profile, {recursive:true, force:true, maxRetries:4});
}
