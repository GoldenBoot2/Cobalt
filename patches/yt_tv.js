// YouTube TV ad handler (kYtTv in adguard_engine.cc is generated from this file by
// patches/embed_js.py; edit here, then run it). Runs in the page script, after kDebugHead
// (gbr = report, gbs = error text, gbmode = test bits from debug.gb.adguard).
// Empties YouTube's ad lists (adPlacements/adSlots/playerAds) at any depth and removes
// "Sponsored" feed cards (list items holding an adSlotRenderer), in answers to
// /youtubei/v1/(player|get_watch|next|browse|search) loaded with fetch() OR XMLHttpRequest.
// Test bits: 16 delete the keys instead of emptying, 32 re-serialise unchanged,
// 128 original text in a new Response (fetch only), 64 handler off.
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
if(m&64){gbr('yt off');return;}
var re=/youtubei\/v1\/(player|get_watch|next|browse|search)/,n=0,nf=0,
ads=['adPlacements','adSlots','playerAds'];
function fix(o,d,f){if(!o||typeof o!=='object'||d>24)return;
if(Array.isArray(o)){for(var i=o.length-1;i>=0;i--){var e=o[i];
if(e&&typeof e==='object'&&e.adSlotRenderer){o.splice(i,1);f.push('adSlotRenderer');}
else fix(e,d+1,f);}return;}
for(var k in o){var v=o[k];if(ads.indexOf(k)>=0){
if(v&&v.length)f.push(k+':'+v.length);if(m&16)delete o[k];else o[k]=[];}
else if(v&&typeof v==='object')fix(v,d+1,f);}}
// Cleans parsed answer j (in place); returns the text to hand to the page.
function proc(j,s,via,inLen){var f=[];if(!(m&(32|128)))fix(j,0,f);
var o=JSON.stringify(j);
var ak={};(o.match(/"(?:ad|\w+Ad)\w*Renderer"/g)||[]).forEach(function(x){ak[x]=1;});
ak=Object.keys(ak).join(',');if(ak)f.push('LEFT:'+ak);
if(n++<3||(f.length&&nf++<40)){var ks=[];if(!Array.isArray(j))for(var k in j)
ks.push(k+':'+JSON.stringify(j[k]).length);
gbr('yt mode='+m+' '+via+' '+(s.match(re)||[''])[1]+(Array.isArray(j)?' array'+j.length:'')
+' in='+inLen+' out='+o.length+' removed='+(f.join(',')||'none')+' play='
+(j.playabilityStatus&&j.playabilityStatus.status)+' '+ks.join(' ').slice(0,240));}
return o;}
var of=window.fetch;
if(of)window.fetch=function(u,opt){var s=String(u&&u.url||u);var p=of.apply(this,arguments);
if(!re.test(s))return p;return p.then(function(r){if(!r||!r.ok||!r.clone)return r;
return r.clone().text().then(function(t){var j;try{j=JSON.parse(t);}catch(e){
gbr('yt not json '+gbs(e));return r;}
var o=proc(j,s,'fetch',t.length);if(m&128)o=t;
var h={};try{r.headers.forEach(function(v,k){h[k]=v;});}catch(e){}
return new Response(o,{status:r.status,statusText:r.statusText,headers:h});},
function(e){gbr('yt text failed '+gbs(e));return r;});});};
// XMLHttpRequest: remember the URL in open(), then wrap the prototype's responseText /
// response getters, so the page reads the cleaned answer whenever and however it reads it.
var X=window.XMLHttpRequest,P=X&&X.prototype;if(!P)return;
var oo=P.open;
P.open=function(mt,u){try{this.__gbu=String(u);}catch(e){}return oo.apply(this,arguments);};
function hook(name){var d=Object.getOwnPropertyDescriptor(P,name);
if(!d||!d.get){gbr('yt xhr no getter '+name);return;}
Object.defineProperty(P,name,{configurable:true,enumerable:d.enumerable,get:function(){
var v=d.get.call(this);var s=this.__gbu;
if(!s||this.readyState!==4||!re.test(s)||v===null||v===undefined||v==='')return v;
var c='__gbc_'+name;if(this[c]!==undefined)return this[c];
try{var obj=typeof v==='object',j=obj?v:JSON.parse(String(v));
var o=proc(j,s,'xhr',obj?-1:String(v).length);this[c]=obj?j:((m&128)?v:o);}
catch(e){gbr('yt xhr '+name+' '+gbs(e));this[c]=v;}
return this[c];}});}
hook('responseText');hook('response');
})();}catch(e){gbr('yt err '+gbs(e));}
