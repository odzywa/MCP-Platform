(function(){
if(typeof window.applyLang==='function'){var s=localStorage.getItem('mcp_lang');if(s==='en')applyLang('en');return;}
{{ trans_raw }}
TRANS_RAW.sort(function(a,b){return b[0].length-a[0].length;});
var TRANS_KEYS=TRANS_RAW.map(function(p){return p[0];});
var TRANS_VALS=TRANS_RAW.map(function(p){return p[1];});
function translateText(text){
for(var i=0;i<TRANS_KEYS.length;i++){
var k=TRANS_KEYS[i];if(text.indexOf(k)===-1)continue;
if(k.length<=6){var ek=k.replace(/[.*+?^${}()|[\]\\]/g,'\\$&');
var re=new RegExp('(?<![a-zA-ZąćęłńóśźżĄĆĘŁŃÓŚŹŻ])'+ek+'(?![a-zA-ZąćęłńóśźżĄĆĘŁŃÓŚŹŻ])','g');
text=text.replace(re,TRANS_VALS[i]);}else{text=text.split(k).join(TRANS_VALS[i]);}}return text;}
function collectNodes(){var w=document.createTreeWalker(document.body,NodeFilter.SHOW_TEXT,null,false);var n,r=[];while((n=w.nextNode())){if(n.textContent.trim())r.push(n);}return r;}
window.applyLang=function(lang){
var toEN=lang==='en';
if(toEN){collectNodes().forEach(function(node){if(node._orig===undefined)node._orig=node.textContent;node.textContent=translateText(node._orig);});
document.querySelectorAll('[placeholder]').forEach(function(el){if(el._origPh===undefined)el._origPh=el.placeholder;el.placeholder=translateText(el._origPh);});
document.querySelectorAll('[title]').forEach(function(el){if(el._origTitle===undefined)el._origTitle=el.title;el.title=translateText(el._origTitle);});
}else{var w=document.createTreeWalker(document.body,NodeFilter.SHOW_TEXT,null,false);var n;while((n=w.nextNode())){if(n._orig!==undefined){n.textContent=n._orig;delete n._orig;}}
document.querySelectorAll('[placeholder]').forEach(function(el){if(el._origPh!==undefined){el.placeholder=el._origPh;delete el._origPh;}});
document.querySelectorAll('[title]').forEach(function(el){if(el._origTitle!==undefined){el.title=el._origTitle;delete el._origTitle;}});}
var p=document.getElementById('btn-pl'),e=document.getElementById('btn-en');
if(p)p.className=!toEN?'lang-active':'';if(e)e.className=toEN?'lang-active':'';
document.documentElement.lang=lang;};
window.setLang=function(lang){localStorage.setItem('mcp_lang',lang);applyLang(lang);};
var saved=localStorage.getItem('mcp_lang')||'pl';
if(saved==='en')applyLang('en');
})();