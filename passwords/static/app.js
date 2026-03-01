let typingTimer;
const doneTypingInterval = 500; // wait 500ms after user stops typing
const passwordInput = document.getElementById('password-input');
const toggleVisBtn = document.getElementById('toggle-visibility');
const eyeIcon = document.getElementById('eye-icon');
const meter = document.getElementById('strength-meter');
const verdictText = document.getElementById('verdict');

const resultsBox = document.getElementById('results');
const valLength = document.getElementById('val-length');
const valEntropy = document.getElementById('val-entropy');
const valPwned = document.getElementById('val-pwned');
const valGuesses = document.getElementById('val-guesses');

const feedbackSection = document.getElementById('feedback-section');
const warningMsg = document.getElementById('warning-msg');
const suggestionsList = document.getElementById('suggestions-list');

const hashCard = document.getElementById('hash-card');
const hashOutput = document.getElementById('hash-output');

// Toggle password visibility
toggleVisBtn.addEventListener('click', () => {
    if (passwordInput.type === 'password') {
        passwordInput.type = 'text';
        // Eye-off icon
        eyeIcon.innerHTML = `<path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path><line x1="1" y1="1" x2="23" y2="23"></line>`;
    } else {
        passwordInput.type = 'password';
        // Eye icon
        eyeIcon.innerHTML = `<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle>`;
    }
});

// Input handling with debounce
passwordInput.addEventListener('input', () => {
    clearTimeout(typingTimer);
    const pwd = passwordInput.value;
    
    if (!pwd) {
        resetUI();
        return;
    }
    
    verdictText.textContent = "Analyzing...";
    verdictText.style.color = 'var(--text-muted)';
    meter.style.width = '10%';
    meter.style.backgroundColor = 'var(--text-muted)';
    
    typingTimer = setTimeout(() => analyzePassword(pwd), doneTypingInterval);
});

function resetUI() {
    meter.style.width = '0%';
    verdictText.textContent = "Start typing...";
    verdictText.style.color = 'var(--text-muted)';
    resultsBox.classList.add('hidden');
    feedbackSection.classList.add('hidden');
    hashCard.classList.add('hidden');
}

async function analyzePassword(pwd) {
    try {
        // Parallel requests to both endpoints
        const [analyzeRes, hashRes] = await Promise.all([
            fetch('/analyze', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ password: pwd })
            }),
            fetch('/hash', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ password: pwd })
            })
        ]);

        if (analyzeRes.ok) {
            const data = await analyzeRes.json();
            updateUI(data);
        } else {
            console.error("API Error");
        }
        
        if (hashRes.ok) {
            const dataHash = await hashRes.json();
            hashOutput.textContent = dataHash.argon2id_hash;
            hashCard.classList.remove('hidden');
        }

    } catch (error) {
        console.error("Network Error: ", error);
        verdictText.textContent = "Error checking password";
    }
}

function updateUI(data) {
    resultsBox.classList.remove('hidden');
    
    // Update Score & Meter
    let meterWidth = '0%';
    let meterColor = 'var(--text-muted)';
    let verdict = '';
    
    // Basic score mapping
    if (data.entropy_score === 0) { meterWidth = '20%'; meterColor = 'var(--strength-0)'; verdict = 'Very Weak'; }
    if (data.entropy_score === 1) { meterWidth = '40%'; meterColor = 'var(--strength-1)'; verdict = 'Weak'; }
    if (data.entropy_score === 2) { meterWidth = '60%'; meterColor = 'var(--strength-2)'; verdict = 'Fair'; }
    if (data.entropy_score === 3) { meterWidth = '80%'; meterColor = 'var(--strength-3)'; verdict = 'Good'; }
    if (data.entropy_score === 4) { meterWidth = '100%'; meterColor = 'var(--strength-4)'; verdict = 'Excellent'; }

    // Override if NIST rules fail
    if (!data.is_valid) {
        if (data.is_pwned) {
            meterWidth = '10%';
            meterColor = 'var(--strength-0)';
            verdict = 'COMPROMISED (PWNED)';
        } else if (data.length < 8) {
            meterWidth = '15%';
            meterColor = 'var(--strength-0)';
            verdict = 'Too Short (NIST Violation)';
        } else {
            meterColor = 'var(--strength-0)';
            verdict = 'Weak (NIST Violation)';
        }
    } else {
        verdict = verdict + " (NIST Compliant)";
    }

    meter.style.width = meterWidth;
    meter.style.backgroundColor = meterColor;
    verdictText.textContent = verdict;
    verdictText.style.color = meterColor;
    
    // Update Boxes
    valLength.textContent = data.length;
    valLength.className = data.length >= 8 ? 'box-value status-good' : 'box-value status-bad';
    
    valEntropy.textContent = data.entropy_score + '/4';
    valEntropy.className = data.entropy_score >= 3 ? 'box-value status-good' : (data.entropy_score < 2 ? 'box-value status-bad' : 'box-value status-warn');
    
    if (data.is_pwned) {
        valPwned.textContent = `Found ${data.pwned_count.toLocaleString()} times`;
        valPwned.className = 'box-value status-bad';
    } else {
        valPwned.textContent = 'Safe';
        valPwned.className = 'box-value status-good';
    }
    
    // Format guesses nicely
    const g = parseFloat(data.estimated_guesses);
    let guessText = g.toExponential(2);
    if (g < 1000) guessText = g.toString();
    else if (g < 1000000) guessText = Math.floor(g/1000) + 'k';
    else if (g < 1000000000) guessText = Math.floor(g/1000000) + 'm';
    else if (g < 1000000000000) guessText = Math.floor(g/1000000000) + 'b';
    
    valGuesses.textContent = guessText;
    
    // Feedback Section
    if (data.feedback_warning || data.feedback_suggestions.length > 0) {
        feedbackSection.classList.remove('hidden');
        
        if (data.feedback_warning) {
            warningMsg.textContent = data.feedback_warning;
            warningMsg.style.display = 'block';
        } else {
            warningMsg.style.display = 'none';
        }
        
        suggestionsList.innerHTML = '';
        data.feedback_suggestions.forEach(s => {
            const li = document.createElement('li');
            li.textContent = s;
            suggestionsList.appendChild(li);
        });
    } else {
        feedbackSection.classList.add('hidden');
    }
}
