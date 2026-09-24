/**
 * PS-AD-Arsenal Frontend Logic
 * Implements Typewriter Terminal Effect and Scroll Animations.
 * Compliant with ISO 27001 (Secure Coding) & OWASP (No eval/innerHTML misuse).
 */

document.addEventListener('DOMContentLoaded', () => {
    initTypewriter();
    initScrollAnimations();
});

/**
 * 1. Typewriter Terminal Effect
 * Simulates a real PowerShell execution of the PS-AD-Arsenal.
 */
function initTypewriter() {
    const outputElement = document.getElementById('typewriter-output');
    if (!outputElement) return;

    // Script sequence to simulate
    const scriptSequence = [
        { text: "PS C:\\> Import-Module .\\PS-AD-Arsenal.psm1", delay: 50 },
        { text: "[+] Module loaded successfully.", delay: 30, color: "#10b981" },
        { text: "PS C:\\> Invoke-ADHardening -Domain 'corp.local' -Mode 'Dual'", delay: 50 },
        { text: "[*] Initializing Blue Team protocols...", delay: 20, color: "#38bdf8" },
        { text: "[*] Disabling SMBv1... [OK]", delay: 40, color: "#10b981" },
        { text: "[*] Renaming local Administrator... [OK]", delay: 40, color: "#10b981" },
        { text: "[*] Deploying Honeypot (Red Team)... [OK]", delay: 40, color: "#f59e0b" },
        { text: "[+] AD DS Hardening completed. System secured.", delay: 30, color: "#10b981" },
        { text: "PS C:\\> _", delay: 0, isCursor: true }
    ];

    let lineIndex = 0;
    let charIndex = 0;

    function typeLine() {
        if (lineIndex >= scriptSequence.length) return;

        const currentLine = scriptSequence[lineIndex];
        
        if (charIndex === 0) {
            const lineDiv = document.createElement('div');
            lineDiv.className = 'terminal-line';
            lineDiv.style.color = currentLine.color || '#10b981';
            lineDiv.style.marginBottom = '0.5rem';
            outputElement.appendChild(lineDiv);
        }

        const currentLineDiv = outputElement.lastElementChild;
        
        if (charIndex < currentLine.text.length) {
            currentLineDiv.textContent += currentLine.text.charAt(charIndex);
            charIndex++;
            setTimeout(typeLine, currentLine.delay);
        } else {
            lineIndex++;
            charIndex = 0;
            setTimeout(typeLine, 300); // Pause between lines
        }
    }

    // Start typing after a short delay
    setTimeout(typeLine, 1000);
}

/**
 * 2. Scroll Animations (Intersection Observer)
 * Triggers fade-in effects when elements enter the viewport.
 */
function initScrollAnimations() {
    const fadeElements = document.querySelectorAll('.fade-in');
    
    const observerOptions = {
        root: null,
        rootMargin: '0px',
        threshold: 0.15 // Trigger when 15% of element is visible
    };

    const observer = new IntersectionObserver((entries, observer) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('visible');
                observer.unobserve(entry.target); // Stop observing once animated
            }
        });
    }, observerOptions);

    fadeElements.forEach(el => observer.observe(el));
}
