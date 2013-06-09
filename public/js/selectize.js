/*! selectize.js - v0.2.2 | https://github.com/brianreavis/selectize.js | Apache License (v2) */
(function(g){"object"===typeof exports?g(require("jquery")):"function"===typeof define&&define.amd?define(["jquery"],g):g(jQuery)})(function(g){var u=function(a,b){if("string"!==typeof b||b.length){var c="string"===typeof b?RegExp(b,"i"):b,d=function(a){var b=0;if(3===a.nodeType){var h=a.data.search(c);if(0<=h&&0<a.data.length){var e=a.data.match(c),b=document.createElement("span");b.className="highlight";a=a.splitText(h);a.splitText(e[0].length);h=a.cloneNode(!0);b.appendChild(h);a.parentNode.replaceChild(b,
a);b=1}}else if(1===a.nodeType&&a.childNodes&&!/(script|style)/i.test(a.tagName))for(h=0;h<a.childNodes.length;++h)h+=d(a.childNodes[h]);return b};return a.each(function(){d(this)})}},q=/Mac/.test(navigator.userAgent),v=q?18:17,m={a:"[a\u00c0\u00c1\u00c2\u00c3\u00c4\u00c5\u00e0\u00e1\u00e2\u00e3\u00e4\u00e5]",c:"[c\u00c7\u00e7]",e:"[e\u00c8\u00c9\u00ca\u00cb\u00e8\u00e9\u00ea\u00eb]",i:"[i\u00cc\u00cd\u00ce\u00cf\u00ec\u00ed\u00ee\u00ef]",n:"[n\u00d1\u00f1]",o:"[o\u00d2\u00d3\u00d4\u00d5\u00d5\u00d6\u00d8\u00f2\u00f3\u00f4\u00f5\u00f6\u00f8]",
s:"[s\u0160\u0161]",u:"[u\u00d9\u00da\u00db\u00dc\u00f9\u00fa\u00fb\u00fc]",y:"[y\u0178\u00ff\u00fd]",z:"[z\u017d\u017e]"},k=function(a){return"undefined"!==typeof a},r=function(a){return String(a).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;")},s=function(a,b,c){var d;b=a.trigger;var f={};a.trigger=function(){f[arguments[0]]=arguments};c.apply(a,[]);a.trigger=b;for(d in f)f.hasOwnProperty(d)&&b.apply(a,f[d])},p=function(a,b,c,d){a.on(b,c,function(b){for(var c=
b.target;c&&c.parentNode!==a[0];)c=c.parentNode;b.currentTarget=c;return d.apply(this,[b])})},t=function(a){var b={};if("selectionStart"in a)b.start=a.selectionStart,b.length=a.selectionEnd-b.start;else if(document.selection){a.focus();var c=document.selection.createRange(),d=document.selection.createRange().text.length;c.moveStart("character",-a.value.length);b.start=c.text.length-d;b.length=d}return b},e=function(a,b){a[0].selectize=this;this.$input=a;this.tagType="select"===a[0].tagName.toLowerCase()?
1:2;this.settings=b;this.highlightedValue=null;this.hasOptions=this.ignoreFocus=this.isCtrlDown=this.isShiftDown=this.isSetup=this.isInputHidden=this.isInputFocused=this.isFocused=this.isLocked=this.isOpen=!1;this.currentResults=null;this.lastValue="";this.loading=this.caretPos=0;this.loadedSearches={};this.$activeOption=null;this.$activeItems=[];this.options={};this.userOptions={};this.items=[];this.renderCache={};var c=this.onSearchChange,d=this.settings.loadThrottle,f;this.onSearchChange=function(){var a=
this,b=arguments;window.clearTimeout(f);f=window.setTimeout(function(){c.apply(a,b)},d)};if(g.isArray(b.options))for(var j=b.valueField,h=0;h<b.options.length;h++)b.options[h].hasOwnProperty(j)&&(this.options[b.options[h][j]]=b.options[h]);else"object"===typeof b.options&&(g.extend(this.options,b.options),delete this.settings.options);this.settings.mode=this.settings.mode||(1===this.settings.maxItems?"single":"multi");"boolean"!==typeof this.settings.hideSelected&&(this.settings.hideSelected="multi"===
this.settings.mode);this.setup()};e.prototype.setup=function(){var a=this,b,c,d,f,j;f=this.$input.attr("tabindex")||"";b=this.$input.attr("class")||"";b=g("<div>").addClass(this.settings.theme).addClass(this.settings.wrapperClass).addClass(b);c=g("<div>").addClass(this.settings.inputClass).addClass("items").toggleClass("has-options",!g.isEmptyObject(this.options)).appendTo(b);d=g('<input type="text">').appendTo(c).attr("tabindex",f);f=g("<div>").addClass(this.settings.dropdownClass).hide().appendTo(b);
b.css({width:this.$input[0].style.width,display:this.$input.css("display")});j=this.settings.mode;b.toggleClass("single","single"===j);b.toggleClass("multi","multi"===j);(null===this.settings.maxItems||1<this.settings.maxItems)&&1===this.tagType&&this.$input.attr("multiple","multiple");this.settings.placeholder&&d.attr("placeholder",this.settings.placeholder);this.$wrapper=b;this.$control=c;this.$control_input=d;this.$dropdown=f;c.on("mousedown",function(b){b.currentTarget===a.$control[0]?d.trigger("focus"):
a.focus(!0);b.preventDefault()});p(f,"mouseenter","*",function(){return a.onOptionHover.apply(a,arguments)});p(f,"mousedown","*",function(){return a.onOptionSelect.apply(a,arguments)});p(c,"mousedown","*:not(input)",function(){return a.onItemSelect.apply(a,arguments)});b=function(a){var b,c;if(!1!==d.data("grow")){a=a||window.event||{};b=d.val();if(a.type&&"keydown"===a.type.toLowerCase()&&(c=a.keyCode,97<=c&&122>=c||65<=c&&90>=c||48<=c&&57>=c||32==c))c=a.shiftKey,a=String.fromCharCode(a.keyCode),
a=c?a.toUpperCase():a.toLowerCase(),b+=a;a=d.attr("placeholder")||"";!b.length&&a.length&&(b=a);b=g("<test>").css({position:"absolute",top:-99999,left:-99999,width:"auto",padding:0,whiteSpace:"nowrap"}).text(b).appendTo("body");a=["letterSpacing","fontSize","fontFamily","fontWeight","textTransform"];c={};if(a)for(var f=0;f<a.length;f++)c[a[f]]=d.css(a[f]);else c=d.css();b.css(c);a=b.width();b.remove();b=a+4;b!==d.width()&&(d.width(b),d.triggerHandler("resize"))}};d.on("keydown keyup update blur",
b);b();d.on({mousedown:function(a){a.stopPropagation()},keydown:function(){return a.onKeyDown.apply(a,arguments)},keyup:function(){return a.onKeyUp.apply(a,arguments)},keypress:function(){return a.onKeyPress.apply(a,arguments)},resize:function(){a.positionDropdown.apply(a,[])},blur:function(){return a.onBlur.apply(a,arguments)},focus:function(){return a.onFocus.apply(a,arguments)}});g(document).on({keydown:function(b){a.isCtrlDown=b[q?"altKey":"ctrlKey"];a.isShiftDown=b.shiftKey;if(a.isFocused&&!a.isLocked){var c=
(b.target.tagName||"").toLowerCase();if(!("input"===c||"textarea"===c)&&-1!==[16,8,46,27,37,39,9].indexOf(b.keyCode))return a.onKeyDown.apply(a,arguments)}},keyup:function(b){b.keyCode===v?a.isCtrlDown=!1:16===b.keyCode&&(a.isShiftDown=!1)},mousedown:function(b){if(a.isFocused)if(b.target===a.$dropdown[0]){var c=a.ignoreFocus;a.ignoreFocus=!0;window.setTimeout(function(){a.ignoreFocus=c;a.focus(!1)},0)}else!a.$control.has(b.target).length&&b.target!==a.$control[0]&&a.blur()}});g(window).on({resize:function(){a.isOpen&&
a.positionDropdown.apply(a,arguments)}});this.$input.attr("tabindex",-1).hide().after(this.$wrapper);g.isArray(this.settings.items)&&(this.setValue(this.settings.items),delete this.settings.items);this.updateOriginalInput();this.refreshItems();this.updatePlaceholder();this.isSetup=!0;if(this.settings.preload)this.onSearchChange("")};e.prototype.trigger=function(a){var b;"function"===typeof this.settings[a]&&(b=Array.prototype.slice.apply(arguments,[1]),this.settings[a].apply(this,b))};e.prototype.onKeyPress=
function(a){if(this.isLocked)return a&&a.preventDefault();var b=String.fromCharCode(a.keyCode||a.which);if(this.settings.create&&b===this.settings.delimiter)return this.createItem(),a.preventDefault(),!1};e.prototype.onKeyDown=function(a){var b=a.keyCode||a.which;if(this.isLocked)9!==b&&a.preventDefault();else{switch(b){case 27:this.blur();return;case 40:!this.isOpen&&this.hasOptions&&this.isInputFocused?this.open():this.$activeOption&&(b=this.$activeOption.next(),b.length&&this.setActiveOption(b,
!0,!0));a.preventDefault();break;case 38:this.$activeOption&&(b=this.$activeOption.prev(),b.length&&this.setActiveOption(b,!0,!0));a.preventDefault();break;case 13:if(this.$activeOption)this.onOptionSelect({currentTarget:this.$activeOption});a.preventDefault();break;case 37:this.advanceSelection(-1,a);break;case 39:this.advanceSelection(1,a);break;case 9:this.settings.create&&g.trim(this.$control_input.val()).length&&(this.createItem(),a.preventDefault());break;case 8:case 46:this.deleteSelection(a);
break;default:if(this.isFull()||this.isInputHidden){a.preventDefault();return}}this.isFull()||this.focus(!0)}};e.prototype.onKeyUp=function(a){if(this.isLocked)return a&&a.preventDefault();a=this.$control_input.val()||"";this.lastValue!==a&&(this.lastValue=a,this.onSearchChange(a),this.refreshOptions(),this.trigger("onType",a))};e.prototype.onSearchChange=function(a){if(this.settings.load&&!this.loadedSearches.hasOwnProperty(a)){var b=this,c=this.$wrapper.addClass("loading");this.loading++;this.loadedSearches[a]=
!0;this.settings.load.apply(this,[a,function(a){b.loading=Math.max(b.loading-1,0);a&&a.length&&(b.addOption(a),b.refreshOptions(!1),b.isInputFocused&&b.open());b.loading||c.removeClass("loading")}])}};e.prototype.onFocus=function(){this.isFocused=this.isInputFocused=!0;this.ignoreFocus||(this.showInput(),this.setActiveItem(null),this.$control.addClass("focus"),this.refreshOptions(!!this.settings.openOnFocus))};e.prototype.onBlur=function(){this.isInputFocused=!1;this.ignoreFocus||(this.close(),this.setTextboxValue(""),
this.setActiveOption(null),this.setCaret(this.items.length,!1),this.$activeItems.length||(this.$control.removeClass("focus"),this.isFocused=!1))};e.prototype.onOptionHover=function(a){this.setActiveOption(a.currentTarget,!1)};e.prototype.onOptionSelect=function(a){a.preventDefault&&a.preventDefault();a.stopPropagation&&a.stopPropagation();this.focus(!1);a=g(a.currentTarget);if(a.hasClass("create"))this.createItem();else if(a=a.attr("data-value"))this.setTextboxValue(""),this.addItem(a)};e.prototype.onItemSelect=
function(a){"multi"===this.settings.mode&&(a.preventDefault(),a.stopPropagation(),this.$control_input.triggerHandler("blur"),this.setActiveItem(a.currentTarget,a),this.focus(!1),this.hideInput())};e.prototype.setTextboxValue=function(a){this.$control_input.val(a).triggerHandler("update");this.lastValue=a};e.prototype.getValue=function(){return 1===this.tagType&&this.$input.attr("multiple")?this.items:this.items.join(this.settings.delimiter)};e.prototype.setValue=function(a){s(this,["change"],function(){this.clear();
for(var b=g.isArray(a)?a:[a],c=0,d=b.length;c<d;c++)this.addItem(b[c])})};e.prototype.setActiveItem=function(a,b){var c,d,f;a=g(a);if(a.length){c=b&&b.type.toLowerCase();if("mousedown"===c&&this.isShiftDown&&this.$activeItems.length){c=this.$control.children(".active:last");d=Array.prototype.indexOf.apply(this.$control[0].childNodes,[c[0]]);c=Array.prototype.indexOf.apply(this.$control[0].childNodes,[a[0]]);d>c&&(f=d,d=c,c=f);for(;d<=c;d++)f=this.$control[0].childNodes[d],-1===this.$activeItems.indexOf(f)&&
(g(f).addClass("active"),this.$activeItems.push(f));b.preventDefault()}else"mousedown"===c&&this.isCtrlDown||"keydown"===c&&this.isShiftDown?a.hasClass("active")?(c=this.$activeItems.indexOf(a[0]),this.$activeItems.splice(c,1),a.removeClass("active")):this.$activeItems.push(a.addClass("active")[0]):(g(this.$activeItems).removeClass("active"),this.$activeItems=[a.addClass("active")[0]]);this.isFocused=!!this.$activeItems.length||this.isInputFocused}else g(this.$activeItems).removeClass("active"),this.$activeItems=
[],this.isFocused=this.isInputFocused};e.prototype.setActiveOption=function(a,b,c){var d,f,j;this.$activeOption&&this.$activeOption.removeClass("active");this.$activeOption=null;a=g(a);if(a.length&&(this.$activeOption=a.addClass("active"),b||!k(b)))a=this.$dropdown.height(),d=this.$activeOption.outerHeight(!0),b=this.$dropdown.scrollTop()||0,f=this.$activeOption.offset().top-this.$dropdown.offset().top+b,j=f-a+d,f+d>a-b?this.$dropdown.stop().animate({scrollTop:j},c?this.settings.scrollDuration:0):
f<b&&this.$dropdown.stop().animate({scrollTop:f},c?this.settings.scrollDuration:0)};e.prototype.hideInput=function(){this.setTextboxValue("");this.$control_input.css({opacity:0,position:"absolute",left:-1E4});this.isInputFocused=!1;this.isInputHidden=!0};e.prototype.showInput=function(){this.$control_input.css({opacity:1,position:"relative",left:0});this.isInputHidden=!1};e.prototype.focus=function(a){var b=this.ignoreFocus,c=a&&!this.isInputFocused;this.ignoreFocus=!a;this.$control_input[0].focus();
if(c)this.onFocus();this.ignoreFocus=b};e.prototype.blur=function(){this.$control_input.trigger("blur");this.setActiveItem(null)};e.prototype.parseSearchTokens=function(a){a=g.trim(String(a||"").toLowerCase());if(!a||!a.length)return[];var b,c,d,f=[],j=a.split(/ +/);a=0;for(b=j.length;a<b;a++){c=(j[a]+"").replace(/([.?*+^$[\]\\(){}|-])/g,"\\$1");if(this.settings.diacritics)for(d in m)m.hasOwnProperty(d)&&(c=c.replace(RegExp(d,"g"),m[d]));f.push({string:j[a],regex:RegExp(c,"i")})}return f};e.prototype.getScoreFunction=
function(a){var b=this,c=a.tokens,d=c.length?1===c.length?function(a){var b;a=String(a||"").toLowerCase();b=a.search(c[0].regex);if(-1===b)return 0;a=c[0].string.length/a.length;0===b&&(a+=0.5);return a}:function(a){var b,d,e,g;a=String(a||"").toLowerCase();e=b=0;for(g=c.length;e<g;e++){d=a.search(c[e].regex);if(-1===d)return 0;0===d&&(b+=0.5);b+=c[e].string.length/a.length}return b/c.length}:function(){return 0};return function(){var a=b.settings.searchField;"string"===typeof a&&(a=[a]);if(!a||!a.length)return function(){return 0};
if(1===a.length){var c=a[0];return function(a){return!a.hasOwnProperty(c)?0:d(a[c])}}return function(b){for(var c=0,e=0,j=0,g=a.length;j<g;j++)b.hasOwnProperty(a[j])&&(e+=d(b[a[j]]),c++);return e/c}}()};e.prototype.search=function(a,b){var c=this,d,f,e,h;b=b||{};a=g.trim(String(a||"").toLowerCase());if(a!==this.lastQuery){this.lastQuery=a;e={query:a,tokens:this.parseSearchTokens(a),total:0,items:[]};if(this.settings.score){if(h=this.settings.score.apply(this,[e]),"function"!==typeof h)throw Error('Selectize "score" setting must be a function that returns a function');
}else h=this.getScoreFunction(e);if(a.length){for(d in this.options)this.options.hasOwnProperty(d)&&(f=h(this.options[d]),0<f&&e.items.push({score:f,value:d}));e.items.sort(function(a,b){return b.score-a.score})}else{for(d in this.options)this.options.hasOwnProperty(d)&&e.items.push({score:1,value:d});this.settings.sortField&&e.items.sort(function(){var a=c.settings.sortField,b="desc"===c.settings.sortDirection?-1:1;return function(d,f){d=d&&String(c.options[d.value][a]||"").toLowerCase();f=f&&String(c.options[f.value][a]||
"").toLowerCase();return d>f?1*b:f>d?-1*b:0}}())}this.currentResults=e}else e=g.extend(!0,{},this.currentResults);return this.prepareResults(e,b)};e.prototype.prepareResults=function(a,b){if(this.settings.hideSelected)for(var c=a.items.length-1;0<=c;c--)-1!==this.items.indexOf(String(a.items[c].value))&&a.items.splice(c,1);a.total=a.items.length;"number"===typeof b.limit&&(a.items=a.items.slice(0,b.limit));return a};e.prototype.refreshOptions=function(a){"undefined"===typeof a&&(a=!0);var b,c,d=this.$control_input.val(),
f=this.search(d,{}),e=[];c=f.items.length;"number"===typeof this.settings.maxOptions&&(c=Math.min(c,this.settings.maxOptions));for(b=0;b<c;b++)e.push(this.render("option",this.options[f.items[b].value]));this.$dropdown.html(e.join(""));if(this.settings.highlight&&f.query.length&&f.tokens.length){b=0;for(c=f.tokens.length;b<c;b++)u(this.$dropdown,f.tokens[b].regex)}if(!this.settings.hideSelected){b=0;for(c=this.items.length;b<c;b++)this.getOption(this.items[b]).addClass("selected")}(b=this.settings.create&&
f.query.length)&&this.$dropdown.prepend(this.render("option_create",{input:d}));(this.hasOptions=0<f.items.length||b)?(this.setActiveOption(this.$dropdown[0].childNodes[b&&0<f.items.length?1:0]),a&&!this.isOpen&&this.open()):(this.setActiveOption(null),a&&this.isOpen&&this.close())};e.prototype.addOption=function(a,b){if(g.isArray(a))for(var c=0,d=a.length;c<d;c++)this.addOption(a[c][this.settings.valueField],a[c]);else this.options.hasOwnProperty(a)||(a=String(a),this.userOptions[a]=!0,this.options[a]=
b,this.lastQuery=null,this.trigger("onOptionAdd",a,b))};e.prototype.updateOption=function(a,b){a=String(a);this.options[a]=b;k(this.renderCache.item)&&delete this.renderCache.item[a];k(this.renderCache.option)&&delete this.renderCache.option[a];if(-1!==this.items.indexOf(a)){var c=this.getItem(a),d=g(this.render("item",b));c.hasClass("active")&&d.addClass("active");c.replaceWith(d)}this.isOpen&&this.refreshOptions(!1)};e.prototype.removeOption=function(a){a=String(a);delete this.userOptions[a];delete this.options[a];
this.lastQuery=null;this.trigger("onOptionRemove",a)};e.prototype.getOption=function(a){return this.$dropdown.children('[data-value="'+a.replace(/(['"])/g,"\\$1")+'"]:first')};e.prototype.getItem=function(a){var b=this.items.indexOf(a);return-1!==b&&(b>=this.caretPos&&b++,b=g(this.$control[0].childNodes[b]),b.attr("data-value")===a)?b:g()};e.prototype.addItem=function(a){s(this,["change"],function(){var b,c=this,d=this.settings.mode;a=String(a);"single"===d&&this.clear();if(!("multi"===d&&this.isFull())&&
(-1===this.items.indexOf(a)&&this.options.hasOwnProperty(a))&&(b=g(this.render("item",this.options[a])),this.items.splice(this.caretPos,0,a),this.insertAtCaret(b),this.refreshClasses(),this.isSetup)){for(var f=this.$dropdown[0].childNodes,e=0;e<f.length;e++){var h=g(f[e]);if(h.attr("data-value")===a){h.remove();h[0]===this.$activeOption[0]&&this.setActiveOption(f.length?g(f[0]).addClass("active"):null);break}}!f.length||null!==this.settings.maxItems&&this.items.length>=this.settings.maxItems?this.close():
this.positionDropdown();this.isFocused&&window.setTimeout(function(){"single"===d?(c.blur(),c.focus(!1),c.hideInput()):c.focus(!1)},0);this.updatePlaceholder();this.trigger("onItemAdd",a,b);this.updateOriginalInput()}})};e.prototype.removeItem=function(a){var b,c;b="object"===typeof a?a:this.getItem(a);a=String(b.attr("data-value"));c=this.items.indexOf(a);-1!==c&&(b.remove(),b.hasClass("active")&&(b=this.$activeItems.indexOf(b[0]),this.$activeItems.splice(b,1)),this.items.splice(c,1),this.lastQuery=
null,!this.settings.persist&&this.userOptions.hasOwnProperty(a)&&this.removeOption(a),this.setCaret(c),this.positionDropdown(),this.refreshOptions(!1),this.refreshClasses(),this.hasOptions?this.isInputFocused&&this.open():this.close(),this.updatePlaceholder(),this.updateOriginalInput(),this.trigger("onItemRemove",a))};e.prototype.createItem=function(){var a=this,b=g.trim(this.$control_input.val()||""),c=this.caretPos;if(b.length){this.lock();var d="function"===typeof this.settings.create?this.settings.create:
function(b){var c={};c[a.settings.labelField]=b;c[a.settings.valueField]=b;return c},f,e=function(b){a.unlock();a.focus(!1);var d=b&&b[a.settings.valueField];d&&(a.setTextboxValue(""),a.addOption(d,b),a.setCaret(c,!1),a.addItem(d),a.refreshOptions(!0),a.focus(!1))},h=!1;f=function(){h||(h=!0,e.apply(this,arguments))};b=d(b,f);"undefined"!==typeof b&&f(b)}};e.prototype.refreshItems=function(){this.lastQuery=null;if(this.isSetup)for(var a=0;a<this.items.length;a++)this.addItem(this.items);this.refreshClasses();
this.updateOriginalInput()};e.prototype.refreshClasses=function(){var a=this.isFull(),b=this.isLocked;this.$control.toggleClass("locked",b);this.$control.toggleClass("full",a).toggleClass("not-full",!a);this.$control.toggleClass("has-items",0<this.items.length);this.$control_input.data("grow",!a&&!b)};e.prototype.isFull=function(){return null!==this.settings.maxItems&&this.items.length>=this.settings.maxItems};e.prototype.updateOriginalInput=function(){var a,b,c;if("select"===this.$input[0].tagName.toLowerCase()){c=
[];a=0;for(b=this.items.length;a<b;a++)c.push('<option value="'+r(this.items[a])+'" selected="selected"></option>');!c.length&&!this.$input.attr("multiple")&&c.push('<option value="" selected="selected"></option>');this.$input.html(c.join(""))}else this.$input.val(this.getValue());this.$input.trigger("change");this.isSetup&&this.trigger("onChange",this.$input.val())};e.prototype.updatePlaceholder=function(){if(this.settings.placeholder){var a=this.$control_input;this.items.length?a.removeAttr("placeholder"):
a.attr("placeholder",this.settings.placeholder);a.triggerHandler("update")}};e.prototype.open=function(){if(!this.isLocked&&!(this.isOpen||"multi"===this.settings.mode&&this.isFull()))this.isOpen=!0,this.positionDropdown(),this.$control.addClass("dropdown-active"),this.$dropdown.show(),this.trigger("onDropdownOpen",this.$dropdown)};e.prototype.close=function(){this.isOpen&&(this.$dropdown.hide(),this.$control.removeClass("dropdown-active"),this.isOpen=!1,this.trigger("onDropdownClose",this.$dropdown))};
e.prototype.positionDropdown=function(){var a=this.$control,b=a.position();b.top+=a.outerHeight(!0);this.$dropdown.css({width:a.outerWidth(),top:b.top,left:b.left})};e.prototype.clear=function(){this.items.length&&(this.$control.children(":not(input)").remove(),this.items=[],this.setCaret(0),this.updatePlaceholder(),this.updateOriginalInput(),this.refreshClasses(),this.trigger("onClear"))};e.prototype.insertAtCaret=function(a){var b=Math.min(this.caretPos,this.items.length);0===b?this.$control.prepend(a):
g(this.$control[0].childNodes[b]).before(a);this.setCaret(b+1)};e.prototype.deleteSelection=function(a){var b,c,d,f;b=8===a.keyCode?-1:1;d=t(this.$control_input[0]);if(this.$activeItems.length){d=this.$control.children(".active:"+(0<b?"last":"first"));d=Array.prototype.indexOf.apply(this.$control[0].childNodes,[d[0]]);1<this.$activeItems.length&&0<b&&d--;f=[];b=0;for(c=this.$activeItems.length;b<c;b++)f.push(g(this.$activeItems[b]).attr("data-value"));for(;f.length;)this.removeItem(f.pop());this.setCaret(d);
a.preventDefault();a.stopPropagation()}else if((this.isInputFocused||"single"===this.settings.mode)&&this.items.length)0>b&&0===d.start&&0===d.length?this.removeItem(this.items[this.caretPos-1]):0<b&&d.start===this.$control_input.val().length&&this.removeItem(this.items[this.caretPos])};e.prototype.advanceSelection=function(a,b){if(0!==a){var c=0<a?"last":"first",d=t(this.$control_input[0]);this.isInputFocused?(c=this.$control_input.val().length,(0>a?0===d.start&&0===d.length:d.start===c)&&!c&&this.advanceCaret(a,
b)):(d=this.$control.children(".active:"+c),d.length&&(d=Array.prototype.indexOf.apply(this.$control[0].childNodes,[d[0]]),this.setCaret(0<a?d+1:d)))}};e.prototype.advanceCaret=function(a,b){if(0!==a){var c=0<a?"next":"prev";this.isShiftDown?(c=this.$control_input[c](),c.length&&(this.blur(),this.setActiveItem(c),b&&b.preventDefault())):this.setCaret(this.caretPos+a)}};e.prototype.setCaret=function(a,b){a="single"===this.settings.mode?this.items.length:Math.max(0,Math.min(this.items.length,a));var c,
d,f,e;f=this.$control.children(":not(input)");c=0;for(d=f.length;c<d;c++)e=g(f[c]).detach(),c<a?this.$control_input.before(e):this.$control.append(e);this.caretPos=a;b&&this.isSetup&&this.focus(!0)};e.prototype.lock=function(){this.close();this.isLocked=!0;this.refreshClasses()};e.prototype.unlock=function(){this.isLocked=!1;this.refreshClasses()};e.prototype.render=function(a,b){k(e);var c,d,f="",e=!1;-1!==["option","item"].indexOf(a)&&(c=b[this.settings.valueField],e=k(c));if(e&&(k(this.renderCache[a])||
(this.renderCache[a]={}),this.renderCache[a].hasOwnProperty(c)))return this.renderCache[a][c];if(this.settings.render&&"function"===typeof this.settings.render[a])f=this.settings.render[a].apply(this,[b]);else switch(d=b[this.settings.labelField],a){case "option":f='<div class="option">'+d+"</div>";break;case "item":f='<div class="item">'+d+"</div>";break;case "option_create":f='<div class="create">Create <strong>'+r(b.input)+"</strong>&hellip;</div>"}k(c)&&(f=f.replace(/^[\\t ]*<([a-z][a-z0-9\-_]*(?:\:[a-z][a-z0-9\-_]*)?)/i,
'<$1 data-value="'+c+'"'));e&&(this.renderCache[a][c]=f);return f};e.defaults={delimiter:",",persist:!0,diacritics:!0,create:!1,highlight:!0,openOnFocus:!0,maxOptions:1E3,maxItems:null,hideSelected:null,preload:!1,scrollDuration:60,loadThrottle:300,dataAttr:"data-data",sortField:null,sortDirection:"asc",valueField:"value",labelField:"text",searchField:["text"],mode:null,theme:"default",wrapperClass:"selectize-control",inputClass:"selectize-input",dropdownClass:"selectize-dropdown",load:null,score:null,
onChange:null,onItemAdd:null,onItemRemove:null,onClear:null,onOptionAdd:null,onOptionRemove:null,onDropdownOpen:null,onDropdownClose:null,onType:null,render:{item:null,option:null,option_create:null}};g.fn.selectize=function(a){var b=g.fn.selectize.defaults;a=a||{};return this.each(function(){var c,d,f,j,h,k,m,n,l=g(this);j=l[0].tagName.toLowerCase();if("string"===typeof a)c=l.data("selectize"),c[a].apply(c,Array.prototype.splice.apply(arguments,1));else{f=a.dataAttr||b.dataAttr;c={};c.placeholder=
l.attr("placeholder");c.options={};c.items=[];if("select"===j){c.maxItems=l.attr("multiple")?null:1;m=l.children();j=0;for(h=m.length;j<h;j++)n=g(m[j]),d=n.attr("value")||"",d.length&&(k=f&&n.attr(f)||{text:n.html(),value:d},"string"===typeof k&&(k=JSON.parse(k)),c.options[d]=k,n.is(":selected")&&c.items.push(d))}else if(d=g.trim(l.val()||""),d.length){f=d.split(a.delimiter||b.delimiter);j=0;for(h=f.length;j<h;j++)c.options[f[j]]={text:f[j],value:f[j]};c.items=f}c=new e(l,g.extend(!0,{},b,c,a));l.data("selectize",
c);l.addClass("selectized")}})};g.fn.selectize.defaults=e.defaults;return e});