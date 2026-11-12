
document.addEventListener("DOMContentLoaded", () => {
    const oldCursor = document.querySelector(".custom-cursor");
    const oldGlow = document.querySelector(".cursor-glow");
    const oldTrail = document.querySelector(".cursor-trail");

    // Remove previous cursor elements.
    oldCursor?.remove();
    oldGlow?.remove();
    oldTrail?.remove();

    if (!window.matchMedia("(pointer: fine)").matches) return;

    // Create the minimal cursor.
    const cursor = document.createElement("div");
    const ring = document.createElement("div");

    cursor.className = "modern-cursor";
    ring.className = "modern-cursor-ring";

    document.body.append(cursor, ring);

    const style = document.createElement("style");
    style.textContent = `
        body.modern-cursor-active,
        body.modern-cursor-active * {
            cursor: none !important;
        }

        .modern-cursor {
            position: fixed;
            top: 0;
            left: 0;
            width: 7px;
            height: 7px;
            background: #ffffff;
            border-radius: 50%;
            box-shadow: 0 0 8px rgba(192, 38, 255, .8);
            transform: translate(-50%, -50%);
            pointer-events: none;
            z-index: 100002;
            opacity: 0;
        }

        .modern-cursor-ring {
            position: fixed;
            top: 0;
            left: 0;
            width: 27px;
            height: 27px;
            border: 1px solid rgba(192, 132, 252, .85);
            border-radius: 50%;
            transform: translate(-50%, -50%);
            pointer-events: none;
            z-index: 100001;
            opacity: 0;
            box-shadow: 0 0 9px rgba(168, 85, 247, .2);
            transition:
                width .2s ease,
                height .2s ease,
                border-color .2s ease,
                background .2s ease;
        }

        .modern-cursor-ring.hovering {
            width: 39px;
            height: 39px;
            border-color: #60a5fa;
            background: rgba(168, 85, 247, .07);
        }

        @media (pointer: coarse) {
            .modern-cursor,
            .modern-cursor-ring {
                display: none;
            }
        }

        @media (prefers-reduced-motion: reduce) {
            .modern-cursor-ring {
                transition: none;
            }
        }
    `;

    document.head.appendChild(style);
    document.body.classList.add("modern-cursor-active");

    let mouseX = -100;
    let mouseY = -100;
    let ringX = mouseX;
    let ringY = mouseY;

    window.addEventListener("mousemove", (event) => {
        mouseX = event.clientX;
        mouseY = event.clientY;

        cursor.style.opacity = "1";
        ring.style.opacity = "1";

        cursor.style.left = mouseX + "px";
        cursor.style.top = mouseY + "px";
    });

    function animate() {
        ringX += (mouseX - ringX) * 0.18;
        ringY += (mouseY - ringY) * 0.18;

        ring.style.left = ringX + "px";
        ring.style.top = ringY + "px";

        requestAnimationFrame(animate);
    }

    animate();

    document.addEventListener("mouseover", (event) => {
        if (event.target.closest("button, a, input, select, textarea")) {
            ring.classList.add("hovering");
        }
    });

    document.addEventListener("mouseout", (event) => {
        if (event.target.closest("button, a, input, select, textarea")) {
            ring.classList.remove("hovering");
        }
    });

    document.addEventListener("mouseleave", () => {
        cursor.style.opacity = "0";
        ring.style.opacity = "0";
    });

    document.addEventListener("mouseenter", () => {
        ring.style.opacity = "1";
    });
});
