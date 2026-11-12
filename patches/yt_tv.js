// YouTube TV ad handler (kYtTv in adguard_engine.cc is generated from this file by
// patches/embed_js.py; edit here, then run it). Runs in the page script, after kDebugHead
// (gbr = report, gbs = error text, gbmode = test bits from debug.gb.adguard).
// Empties YouTube's ad lists (adPlacements/adSlots/playerAds) at any depth and removes
// "Sponsored" feed cards (list items holding an adSlotRenderer), in answers to
// /youtubei/v1/(player|get_watch|next|browse|search) loaded with fetch() OR XMLHttpRequest.
// Test bits: 16 delete the keys instead of emptying, 32 re-serialise unchanged,
// 128 original text in a new Response (fetch only), 64 handler off, 256 diagnostics
// (every answer parsed + streaming/SSAP/leftover report), 2048 no no-ad request flag,
// 4096 no 720p resolution cap.
try{(function(){
var m=(typeof gbmode==='number'?gbmode:0);
// Bit 512: trace every fetch / XHR / Worker the page starts (where do answers come from?).
if(m&512){try{var tn=0;function tr(w,u){if(tn++<120)gbr('trace '+w+' '+String(u).slice(0,170));}
var tf=window.fetch;if(tf)window.fetch=function(u){tr('fetch',u&&u.url||u);return tf.apply(this,arguments);};
var TX=window.XMLHttpRequest;if(TX&&TX.prototype){var to=TX.prototype.open;
TX.prototype.open=function(mt,u){if(String(u).indexOf('gb-debug.invalid')<0)tr('xhr '+mt,u);return to.apply(this,arguments);};}
var TW=window.Worker;if(TW)window.Worker=function(u,o){tr('worker',u);return new TW(u,o);};
tr('env','sw='+!!(navigator.serviceWorker)+' ctl='+!!(navigator.serviceWorker&&navigator.serviceWorker.controller)
+' worker='+!!TW+' sab='+(typeof SharedArrayBuffer));}catch(e){gbr('trace err '+gbs(e));}}
// Resolution cap: the TV panel is 1280x720, but YouTube picked VP9 1080p (itag 248); the
// decoder then works on 1080p frames that are scaled down (shimmer, more CPU/RAM). Formats
// taller than 720 are reported unsupported, so YouTube picks 720p. Bit 4096 turns it off.
if(!(m&4096)){try{var MS=window.MediaSource,cap=720,nc=0;
if(MS&&MS.isTypeSupported){var its=MS.isTypeSupported;
MS.isTypeSupported=function(t){var s=String(t),h=s.match(/height=(\d+)/);
if(h&&+h[1]>cap){if(nc++<3)gbr('yt cap '+s.slice(0,100));return false;}
return its.apply(MS,arguments);};}else gbr('yt cap: no MediaSource.isTypeSupported');}
catch(e){gbr('yt cap err '+gbs(e));}}
if(m&64){gbr('yt off');return;}
var re=/youtubei\/v1\/(player|get_watch|next|browse|search)/,n=0,nf=0,
ads=['adPlacements','adSlots','playerAds'];
var JP=JSON.parse,JS=JSON.stringify,np=0,nq=0;
// Like TizenTube (reisxd/TizenTube mods/features/adblock.js): video requests carry
// playbackContext.contentPlaybackContext; isInlinePlaybackNoAd=true asks the server for
// playback WITHOUT ads, which also stops ads it would insert into the SABR stream itself.
// Bit 2048 leaves requests unchanged (to compare).
if(!(m&2048))JSON.stringify=function(v,r,sp){try{var c=v&&v.playbackContext&&v.playbackContext.contentPlaybackContext;
if(c&&typeof c==='object'&&c.isInlinePlaybackNoAd!==true){var cp=JP(JS(v));
cp.playbackContext.contentPlaybackContext.isInlinePlaybackNoAd=true;
if(nq++<10)gbr('yt request no-ad flag set'+(v.videoId?' '+v.videoId:''));return JS.call(this,cp,r,sp);}}catch(e){}
return JS.apply(this,arguments);};
// The same flag set directly in the request BODY as it is sent (XHR send / fetch body):
// YouTube TV builds its player requests with its own JSON copy, so the stringify hook
// alone never fired on the TV. get_watch bodies hold the request in playerRequest.
var rq=/youtubei\/v1\/(player|get_watch)/;
function flag(q,d){if(!q||typeof q!=='object'||d>3)return 0;var c=q.playbackContext&&q.playbackContext.contentPlaybackContext;
if(c&&typeof c==='object'){if(c.isInlinePlaybackNoAd===true)return 0;c.isInlinePlaybackNoAd=true;return 1;}
var k,h=0;for(k in q)if(q[k]&&typeof q[k]==='object')h+=flag(q[k],d+1);return h;}
function noad(b,u,via){if(m&2048||typeof b!=='string'||!rq.test(String(u))||b.indexOf('contentPlaybackContext')<0)return b;
try{var q=JP(b);if(flag(q,0)){b=JS(q);if(nq++<20)gbr('yt request no-ad flag set via '+via+' '+(String(u).match(rq)||[''])[1]
+(q.videoId?' '+q.videoId:(q.playerRequest&&q.playerRequest.videoId?' '+q.playerRequest.videoId:'')));}}
catch(e){gbr('yt request flag failed '+gbs(e));}return b;}
// Safety net, also like TizenTube: any JSON the page parses gets its top-level ad lists
// emptied (answers that reach the page by other ways than our fetch/XHR hooks).
JSON.parse=function(){var r=JP.apply(this,arguments);try{if(r&&typeof r==='object'){
var o=Array.isArray(r)?r.slice(0,4):[r],hit=0;for(var i=0;i<o.length;i++){var x=o[i];
if(!x||typeof x!=='object')continue;var ys=[x,x.playerResponse];for(var y=0;y<2;y++){var z=ys[y];
if(!z||typeof z!=='object')continue;for(var a=0;a<3;a++){var k=ads[a];
if(z[k]&&z[k].length){hit++;z[k]=[];}}}}if(hit&&np++<20)gbr('yt parse removed '+hit);}}catch(e){}return r;};
function fix(o,d,f){if(!o||typeof o!=='object'||d>24)return;
if(Array.isArray(o)){for(var i=o.length-1;i>=0;i--){var e=o[i];
if(e&&typeof e==='object'&&e.adSlotRenderer){o.splice(i,1);f.push('adSlotRenderer');}
else fix(e,d+1,f);}return;}
for(var k in o){var v=o[k];if(ads.indexOf(k)>=0){
if(v&&v.length)f.push(k+':'+v.length);if(m&16)delete o[k];else o[k]=[];}
else if(v&&typeof v==='object')fix(v,d+1,f);}}
// Streaming details of player answers (SABR = videoplayback POST stream, which can carry
// server-inserted ads). Bit 1024 drops the SABR URL so the player uses the classic formats.
function sabr(j,f,d){if(!j||typeof j!=='object'||d>3)return;
if(Array.isArray(j)){for(var i=0;i<j.length;i++)sabr(j[i],f,d+1);return;}
var sd=j.streamingData;if(sd&&typeof sd==='object'){
var af=sd.adaptiveFormats||[],a0=af[0]||{};
f.push('SD:'+Object.keys(sd).join('/')+' fmt='+af.length+(a0.url?' url':'')+(a0.signatureCipher?' cipher':''));
if((m&1024)&&sd.serverAbrStreamingUrl){delete sd.serverAbrStreamingUrl;f.push('SABR-DROPPED');}}
if(j.playerResponse)sabr(j.playerResponse,f,d+1);}
// Quick test on the raw text: does the answer hold a non-empty ad list or a Sponsored card?
// Answers without one are handed on untouched (no parse / re-serialise on the TV's slow CPU).
var adre=/"(?:adPlacements|adSlots|playerAds)":\s*\[\s*[^\]\s]|"adSlotRenderer"/;
function hasAds(t){return adre.test(t);}
var fast=!(m&(32|128|256));
// Cleans parsed answer j (in place); returns the text to hand to the page (null = j is
// an object answer, already cleaned in place). Diagnostics only with bit 256.
function proc(j,s,via,inLen,txt){var f=[];if(!(m&(32|128)))fix(j,0,f);var dbg=m&256;
if(dbg)sabr(j,f,0);
var o=(txt||dbg)?JS(j):null;
if(dbg){var sp=o.match(/"[^"]*(?:ssap|Ssap|SSAP|serverStitched|ServerStitched)[^"]*"/g);
if(sp){var su={};sp.forEach(function(x){su[x.slice(0,40)]=1;});f.push('SSAP:'+Object.keys(su).slice(0,6).join(','));}
var ak={};(o.match(/"(?:ad|\w+Ad)\w*Renderer"/g)||[]).forEach(function(x){ak[x]=1;});
ak=Object.keys(ak).join(',');if(ak)f.push('LEFT:'+ak);}
if(n++<3||(f.length&&nf++<40)){var ks=[];if(dbg&&!Array.isArray(j))for(var k in j)
ks.push(k+':'+JS(j[k]).length);
gbr('yt mode='+m+' '+via+' '+(s.match(re)||[''])[1]+(Array.isArray(j)?' array'+j.length:'')
+' in='+inLen+' out='+(o?o.length:-1)+' removed='+(f.join(',')||'none')+' play='
+(j.playabilityStatus&&j.playabilityStatus.status)+' '+ks.join(' ').slice(0,240));}
return o;}
// Counts answers passed on untouched (first 3 reported, so the log shows the fast path).
var nskip=0;function skip(s,via,len){if(nskip++<3)gbr('yt mode='+m+' '+via+' '+(s.match(re)||[''])[1]+' in='+len+' no ads, untouched');}
var of=window.fetch;
if(of)window.fetch=function(u,opt){var s=String(u&&u.url||u);
if(opt&&typeof opt.body==='string'&&rq.test(s)){var nb=noad(opt.body,s,'fetch');if(nb!==opt.body){
var o2={};for(var k in opt)o2[k]=opt[k];o2.body=nb;arguments[1]=o2;}}
var p=of.apply(this,arguments);
if(!re.test(s))return p;return p.then(function(r){if(!r||!r.ok||!r.clone)return r;
return r.clone().text().then(function(t){if(fast&&!hasAds(t)){skip(s,'fetch',t.length);return r;}
var j;try{j=JP(t);}catch(e){
gbr('yt not json '+gbs(e));return r;}
var o=proc(j,s,'fetch',t.length,1);if(m&128)o=t;
var h={};try{r.headers.forEach(function(v,k){h[k]=v;});}catch(e){}
return new Response(o,{status:r.status,statusText:r.statusText,headers:h});},
function(e){gbr('yt text failed '+gbs(e));return r;});});};
// XMLHttpRequest: remember the URL in open(), then wrap the prototype's responseText /
// response getters, so the page reads the cleaned answer whenever and however it reads it.
var X=window.XMLHttpRequest,P=X&&X.prototype;if(!P)return;
var oo=P.open;
P.open=function(mt,u){try{this.__gbu=String(u);}catch(e){}return oo.apply(this,arguments);};
var os=P.send;
P.send=function(b){if(typeof b==='string'&&this.__gbu)arguments[0]=noad(b,this.__gbu,'xhr');
return os.apply(this,arguments);};
function hook(name){var d=Object.getOwnPropertyDescriptor(P,name);
if(!d||!d.get){gbr('yt xhr no getter '+name);return;}
Object.defineProperty(P,name,{configurable:true,enumerable:d.enumerable,get:function(){
var v=d.get.call(this);var s=this.__gbu;
if(!s||this.readyState!==4||!re.test(s)||v===null||v===undefined||v==='')return v;
var c='__gbc_'+name;if(this[c]!==undefined)return this[c];
try{var obj=typeof v==='object';
if(!obj&&fast&&!hasAds(String(v))){skip(s,'xhr',String(v).length);this[c]=v;return v;}
var j=obj?v:JP(String(v));
var o=proc(j,s,'xhr',obj?-1:String(v).length,!obj);this[c]=obj?j:((m&128)?v:o);}
catch(e){gbr('yt xhr '+name+' '+gbs(e));this[c]=v;}
return this[c];}});}
hook('responseText');hook('response');
})();}catch(e){gbr('yt err '+gbs(e));}
