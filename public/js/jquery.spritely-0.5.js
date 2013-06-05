/
*(function(e){e._spritely={animate:function(t){var n=e(t.el);var r=n.attr("id");if(!e._spritely.instances[r]){return this}t=e.extend(t,e._spritely.instances[r]||{});if(t.play_frames&&!e._spritely.instances[r]["remaining_frames"]){e._spritely.instances[r]["remaining_frames"]=t.play_frames+1}if(t.type=="sprite"&&t.fps){var i;var s=function(n){var s=t.width,o=t.height;if(!i){i=[];total=0;for(var u=0;u<t.no_of_frames;u++){i[i.length]=0-total;total+=s}}if(t.rewind==true){if(e._spritely.instances[r]["current_frame"]<=0){e._spritely.instances[r]["current_frame"]=i.length-1}else{e._spritely.instances[r]["current_frame"]=e._spritely.instances[r]["current_frame"]-1}}else{if(e._spritely.instances[r]["current_frame"]>=i.length-1){e._spritely.instances[r]["current_frame"]=0}else{e._spritely.instances[r]["current_frame"]=e._spritely.instances[r]["current_frame"]+1}}var a=e._spritely.getBgY(n);n.css("background-position",i[e._spritely.instances[r]["current_frame"]]+"px "+a);if(t.bounce&&t.bounce[0]>0&&t.bounce[1]>0){var f=t.bounce[0];var l=t.bounce[1];var c=t.bounce[2];n.animate({top:"+="+f+"px",left:"-="+l+"px"},c).animate({top:"-="+f+"px",left:"+="+l+"px"},c)}};if(e._spritely.instances[r]["remaining_frames"]&&e._spritely.instances[r]["remaining_frames"]>0){e._spritely.instances[r]["remaining_frames"]--;if(e._spritely.instances[r]["remaining_frames"]==0){e._spritely.instances[r]["remaining_frames"]=-1;delete e._spritely.instances[r]["remaining_frames"];return}else{s(n)}}else if(e._spritely.instances[r]["remaining_frames"]!=-1){s(n)}}else if(t.type=="pan"){if(!e._spritely.instances[r]["_stopped"]){if(t.dir=="up"){e._spritely.instances[r]["l"]=e._spritely.getBgX(n).replace("px","");e._spritely.instances[r]["t"]=e._spritely.instances[r]["t"]-(t.speed||1)||0}else if(t.dir=="down"){e._spritely.instances[r]["l"]=e._spritely.getBgX(n).replace("px","");e._spritely.instances[r]["t"]=e._spritely.instances[r]["t"]+(t.speed||1)||0}else if(t.dir=="left"){e._spritely.instances[r]["l"]=e._spritely.instances[r]["l"]-(t.speed||1)||0;e._spritely.instances[r]["t"]=e._spritely.getBgY(n).replace("px","")}else{e._spritely.instances[r]["l"]=e._spritely.instances[r]["l"]+(t.speed||1)||0;e._spritely.instances[r]["t"]=e._spritely.getBgY(n).replace("px","")}var o=e._spritely.instances[r]["l"].toString();if(o.indexOf("%")==-1){o+="px "}else{o+=" "}var u=e._spritely.instances[r]["t"].toString();if(u.indexOf("%")==-1){u+="px "}else{u+=" "}e(n).css("background-position",o+u)}}e._spritely.instances[r]["options"]=t;window.setTimeout(function(){e._spritely.animate(t)},parseInt(1e3/t.fps))
}, randomIntBetween: function (e, t) {
    return parseInt(rand_no = Math.floor((t - (e - 1)) * Math.random()) + e)
},
    getBgY: function (t) {
        if (e.browser.msie) {
            var n = e(t).css("background-position-y") || "0"
        } else {
            var n = (e(t).css("background-position") || " ").split(" ")[1]
        }
        return n
    },
    getBgX: function (t) {
        if (e.browser.msie) {
            var n = e(t).css("background-position-x") || "0"
        } else {
            var n = (e(t).css("background-position") || " ").split(" ")[0]
        }
        return n
    },
    get_rel_pos: function (e, t) {
        var n = e;
        if (e < 0) {
            while (n < 0) {
                n += t
            }
        } else {
            while (n > t) {
                n -= t
            }
        }
        return n
    }
};
    e.fn.extend({
        spritely: function (t) {
            var t = e.extend({
                type: "sprite",
                do_once: false,
                width: null,
                height: null,
                fps: 12,
                no_of_frames: 2,
                stop_after: null
            }, t || {});
            var n = e(this).attr("id");
            if (!e._spritely.instances) {
                e._spritely.instances = {}
            }
            if (!e._spritely.instances[n]) {
                e._spritely.instances[n] = {
                    current_frame: -1
                }
            }
            e._spritely.instances[n]["type"] = t.type;
            e._spritely.instances[n]["depth"] = t.depth;
            t.el = this;
            t.width = t.width || e(this).width() || 100;
            t.height = t.height || e(this).height() || 100;
            var r = function () {
                return parseInt(1e3 / t.fps)
            };
            if (!t.do_once) {
                window.setTimeout(function () {
                    e._spritely.animate(t)
                }, r(t.fps))
            } else {
                e._spritely.animate(t)
            }
            return this
        },
        sprite: function (t) {
            var t = e.extend({
                type: "sprite",
                bounce: [0, 0, 1e3]
            }, t || {});
            return e(this).spritely(t)
        },
        pan: function (t) {
            var t = e.extend({
                type: "pan",
                dir: "left",
                continuous: true,
                speed: 1
            }, t || {});
            return e(this).spritely(t)
        },
        flyToTap: function (t) {
            var t = e.extend({
                el_to_move: null,
                type: "moveToTap",
                ms: 1e3,
                do_once: true
            }, t || {});
            if (t.el_to_move) {
                e(t.el_to_move).active()
            }
            if (e._spritely.activeSprite) {
                if (window.Touch) {
                    e(this)[0].ontouchstart = function (t) {
                        var n = e._spritely.activeSprite;
                        var r = t.touches[0];
                        var i = r.pageY - n.height() / 2;
                        var s = r.pageX - n.width() / 2;
                        n.animate({
                            top: i + "px",
                            left: s + "px"
                        }, 1e3)
                    }
                } else {
                    e(this).click(function (t) {
                        var n = e._spritely.activeSprite;
                        e(n).stop(true);
                        var r = n.width();
                        var i = n.height();
                        var s = t.pageX - r / 2;
                        var o = t.pageY - i / 2;
                        n.animate({
                            top: o + "px",
                            left: s + "px"
                        }, 1e3)
                    })
                }
            }
            return this
        },
        isDraggable: function (t) {
            if (!e(this).draggable) {
                return this
            }
            var t = e.extend({
                type: "isDraggable",
                start: null,
                stop: null,
                drag: null
            }, t || {});
            var n = e(this).attr("id");
            if (!e._spritely.instances[n]) {
                return this
            }
            e._spritely.instances[n].isDraggableOptions = t;
            e(this).draggable({
                start: function () {
                    var t = e(this).attr("id");
                    e._spritely.instances[t].stop_random = true;
                    e(this).stop(true);
                    if (e._spritely.instances[t].isDraggableOptions.start) {
                        e._spritely.instances[t].isDraggableOptions.start(this)
                    }
                },
                drag: t.drag,
                stop: function () {
                    var t = e(this).attr("id");
                    e._spritely.instances[t].stop_random = false;
                    if (e._spritely.instances[t].isDraggableOptions.stop) {
                        e._spritely.instances[t].isDraggableOptions.stop(this)
                    }
                }
            });
            return this
        },
        active: function () {
            e._spritely.activeSprite = this;
            return this
        },
        activeOnClick: function () {
            var t = e(this);
            if (window.Touch) {
                t[0].ontouchstart = function (n) {
                    e._spritely.activeSprite = t
                }
            } else {
                t.click(function (n) {
                    e._spritely.activeSprite = t
                })
            }
            return this
        },
        spRandom: function (t) {
            var t = e.extend({
                top: 50,
                left: 50,
                right: 290,
                bottom: 320,
                speed: 4e3,
                pause: 0
            }, t || {});
            var n = e(this).attr("id");
            if (!e._spritely.instances[n]) {
                return this
            }
            if (!e._spritely.instances[n].stop_random) {
                var r = e._spritely.randomIntBetween;
                var i = r(t.top, t.bottom);
                var s = r(t.left, t.right);
                e("#" + n).animate({
                    top: i + "px",
                    left: s + "px"
                }, t.speed)
            }
            window.setTimeout(function () {
                e("#" + n).spRandom(t)
            }, t.speed + t.pause);
            return this
        },
        makeAbsolute: function () {
            return this.each(function () {
                var t = e(this);
                var n = t.position();
                t.css({
                    position: "absolute",
                    marginLeft: 0,
                    marginTop: 0,
                    top: n.top,
                    left: n.left
                }).remove().appendTo("body")
            })
        },
        spSet: function (t, n) {
            var r = e(this).attr("id");
            e._spritely.instances[r][t] = n;
            return this
        },
        spGet: function (t, n) {
            var r = e(this).attr("id");
            return e._spritely.instances[r][t]
        },
        spStop: function (t) {
            e(this).each(function () {
                var n = e(this).attr("id");
                e._spritely.instances[n]["_last_fps"] = e(this).spGet("fps");
                e._spritely.instances[n]["_stopped"] = true;
                e._spritely.instances[n]["_stopped_f1"] = t;
                if (e._spritely.instances[n]["type"] == "sprite") {
                    e(this).spSet("fps", 0)
                }
                if (t) {
                    var r = e._spritely.getBgY(e(this));
                    e(this).css("background-position", "0 " + r)
                }
            });
            return this
        },
        spStart: function () {
            e(this).each(function () {
                var t = e(this).attr("id");
                var n = e._spritely.instances[t]["_last_fps"] || 12;
                e._spritely.instances[t]["_stopped"] = false;
                if (e._spritely.instances[t]["type"] == "sprite") {
                    e(this).spSet("fps", n)
                }
            });
            return this
        },
        spToggle: function () {
            var t = e(this).attr("id");
            var n = e._spritely.instances[t]["_stopped"] || false;
            var r = e._spritely.instances[t]["_stopped_f1"] || false;
            if (n) {
                e(this).spStart()
            } else {
                e(this).spStop(r)
            }
            return this
        },
        fps: function (t) {
            e(this).each(function () {
                e(this).spSet("fps", t)
            });
            return this
        },
        spSpeed: function (t) {
            e(this).each(function () {
                e(this).spSet("speed", t)
            });
            return this
        },
        spRelSpeed: function (t) {
            e(this).each(function () {
                var n = e(this).spGet("depth") / 100;
                e(this).spSet("speed", t * n)
            });
            return this
        },
        spChangeDir: function (t) {
            e(this).each(function () {
                e(this).spSet("dir", t)
            });
            return this
        },
        spState: function (t) {
            e(this).each(function () {
                var r = (t - 1) * e(this).height() + "px";
                var i = e._spritely.getBgX(e(this));
                var s = i + " -" + r;
                e(this).css("background-position", s)
            });
            return this
        },
        lockTo: function (t, n) {
            e(this).each(function () {
                var r = e(this).attr("id");
                if (!e._spritely.instances[r]) {
                    return this
                }
                e._spritely.instances[r]["locked_el"] = e(this);
                e._spritely.instances[r]["lock_to"] = e(t);
                e._spritely.instances[r]["lock_to_options"] = n;
                window.setInterval(function () {
                    if (e._spritely.instances[r]["lock_to"]) {
                        var t = e._spritely.instances[r]["locked_el"];
                        var n = e._spritely.instances[r]["lock_to"];
                        var i = e._spritely.instances[r]["lock_to_options"];
                        var s = i.bg_img_width;
                        var o = n.height();
                        var u = e._spritely.getBgY(n);
                        var a = e._spritely.getBgX(n);
                        var f = parseInt(a) + parseInt(i["left"]);
                        var l = parseInt(u) + parseInt(i["top"]);
                        f = e._spritely.get_rel_pos(f, s);
                        e(t).css({
                            top: l + "px",
                            left: f + "px"
                        })
                    }
                }, n.interval || 20)
            });
            return this
        },
        destroy: function () {
            var t = e(this);
            var n = e(this).attr("id");
            delete e._spritely.instances[n];
            return this
        }
    })
})(jQuery);
try {
    document.execCommand("BackgroundImageCache", false, true)
} catch (err) {}