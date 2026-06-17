/* Ki motion: scroll reveals + scroll-driven walkthrough + tracker count-up.
   Vanilla, no deps. Respects prefers-reduced-motion. */
(function () {
    var reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    // Mark JS-on so CSS only hides [data-reveal]/stages when we can reveal them.
    document.documentElement.classList.add("motion-on");

    // Scroll reveals: [data-reveal] elements get .in-view when visible.
    var revealables = document.querySelectorAll("[data-reveal]");
    if (reduced || !("IntersectionObserver" in window)) {
        revealables.forEach(function (el) { el.classList.add("in-view"); });
    } else {
        var io = new IntersectionObserver(function (entries) {
            entries.forEach(function (entry) {
                if (entry.isIntersecting) {
                    entry.target.classList.add("in-view");
                    io.unobserve(entry.target);
                }
            });
        }, { threshold: 0.18 });
        revealables.forEach(function (el) { io.observe(el); });
    }

    var scrolly = document.querySelector(".scrolly");
    if (!scrolly) return;

    // Count the blocked-tracker tally up from 0 when step 2 first activates.
    function countUp() {
        scrolly.querySelectorAll(".ki-count").forEach(function (el) {
            if (el.dataset.done) return;
            el.dataset.done = "1";
            var to = parseInt(el.dataset.to || "0", 10);
            if (reduced) { el.textContent = to; return; }
            var start = null;
            function tick(ts) {
                if (!start) start = ts;
                var p = Math.min((ts - start) / 650, 1);
                el.textContent = Math.round(p * to);
                if (p < 1) requestAnimationFrame(tick);
            }
            requestAnimationFrame(tick);
        });
    }

    // Scrollytelling: as each .scrolly-step crosses mid-viewport, stamp its
    // index on the .scrolly root — CSS swaps the sticky stage state.
    var steps = scrolly.querySelectorAll(".scrolly-step");
    if (reduced || !("IntersectionObserver" in window)) {
        scrolly.setAttribute("data-step", steps.length);
        countUp();
    } else {
        var sio = new IntersectionObserver(function (entries) {
            entries.forEach(function (entry) {
                if (entry.isIntersecting) {
                    scrolly.setAttribute("data-step", entry.target.dataset.index);
                    if (entry.target.dataset.index === "2") countUp();
                }
            });
        }, { rootMargin: "-45% 0px -45% 0px" });
        steps.forEach(function (step) { sio.observe(step); });
    }
})();
