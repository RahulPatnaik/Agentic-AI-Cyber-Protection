# 3-MINUTE VIDEO DEMO SCRIPT
## Agentic Threat Modeling System - TECHGIUM

---

## 🎬 SETUP (Before Recording)

### 1. Start the Application
```bash
cd /home/rahul/Desktop/TECHGIUM/Agentic-Threat-Modeling
MISTRAL_API_KEY=DVKZcAkn2LDdQEBUvR6UgINGY4ZWTKTi python main.py
```

### 2. Open Browser
Navigate to: **http://localhost:8000/dashboard**

---

## 🎥 VIDEO SCRIPT (3 Minutes)

### **[0:00 - 0:20] INTRODUCTION (20 seconds)**

**What to Say:**
> "Welcome to the TECHGIUM Agentic Threat Modeling System. This is an AI-powered security analysis platform built with Pydantic AI and Mistral AI that automatically identifies vulnerabilities using OWASP Top 10, CWE database, and MAESTRO security principles. Let me show you how it works."

**What to Show:**
- Pan across the dashboard showing the tactical military-style interface
- Highlight the status indicators showing "AGENTS: OPERATIONAL"

---

### **[0:20 - 1:00] DEMO SCENARIO 1: JWT Authentication System (40 seconds)**

**What to Say:**
> "Let's analyze a real-world scenario: a JWT-based authentication system. I'll paste a description of our system."

**What to Type in "TARGET SYSTEM DESCRIPTION":**
```
A user authentication API built with Node.js and Express. Users register with email/password, which are stored in MongoDB. Upon login, the system generates JWT tokens with 24-hour expiration. The API has endpoints for user registration, login, password reset, and profile updates. JWT tokens are sent in response headers and must be included in subsequent requests. Password reset sends a reset link via email with a temporary token.
```

**What to Type in "CODE INTEL (OPTIONAL)":**
```javascript
// Login endpoint
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;

    // Find user in database
    const user = await db.collection('users').findOne({ email: email });

    if (!user || user.password !== password) {
        return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Generate JWT token
    const token = jwt.sign(
        { userId: user._id, email: user.email },
        'secret-key-12345',
        { expiresIn: '24h' }
    );

    res.json({ token: token, userId: user._id });
});

// Password reset endpoint
app.post('/api/reset-password', async (req, res) => {
    const { email } = req.body;
    const resetToken = Math.random().toString(36);

    await db.collection('users').update(
        { email: email },
        { $set: { resetToken: resetToken } }
    );

    const resetLink = `http://myapp.com/reset?token=${resetToken}`;
    sendEmail(email, 'Reset your password', resetLink);

    res.json({ message: 'Reset email sent' });
});
```

**What to Do:**
1. Scroll down and check **"PCI-DSS"** and **"GDPR"** compliance checkboxes
2. Click **"INITIATE THREAT ANALYSIS"** button

**What to Say:**
> "I'll click Initiate Threat Analysis. Watch as six AI agents work in parallel: the DFD builder maps the architecture, the threat generator auto-detects vulnerabilities, OWASP analyzer scans for Top 10 issues, and three more agents perform deep analysis."

**What to Show:**
- Loading screen with all 6 agents showing progress
- Wait 10-15 seconds for analysis

---

### **[1:00 - 2:00] RESULTS ANALYSIS (60 seconds)**

**What to Say:**
> "And here are the results. Look at this - the system found multiple critical vulnerabilities."

**What to Show & Say:**

1. **Stats Cards** (5 seconds)
   > "We have several critical and high-severity vulnerabilities detected, along with multiple attack paths mapped."

2. **Data Flow Diagram** (15 seconds)
   > "First, the DFD Builder created this system architecture diagram showing our processes, data stores, data flows, and trust boundaries. Notice how it automatically identified the internet-facing components and database connections."
   - Scroll to show the DFD diagram with Mermaid visualization

3. **Attack Path Visualization** (15 seconds)
   > "Next, the Attack Tree shows end-to-end attack paths. See how attackers could exploit the hardcoded secret key to forge tokens, or use SQL injection to compromise the database."
   - Point to attack paths in the Mermaid graph

4. **Critical Vulnerabilities** (20 seconds)
   > "Here are the top vulnerabilities with severity ratings. Notice: Hardcoded JWT secret key - CWE-798, plaintext password comparison - CWE-257, SQL Injection risk - CWE-89, and missing input validation. Each vulnerability includes the OWASP category, CWE mapping, risk score, and specific remediation steps."
   - Scroll through vulnerability cards
   - Click to expand one vulnerability to show detailed remediation

5. **CWE Intelligence** (5 seconds)
   > "The CWE mapper automatically classified each weakness with Common Weakness Enumeration IDs."
   - Show CWE grid

---

### **[2:00 - 2:40] DEMO SCENARIO 2: Quick Analysis (40 seconds)**

**What to Say:**
> "Let me show you another quick example. I'll click New Analysis."

**What to Do:**
1. Click **"NEW ANALYSIS"** button
2. Clear the form

**What to Type in "TARGET SYSTEM DESCRIPTION":**
```
A file upload service that allows users to upload profile pictures. Files are stored in /uploads directory on the server. The system accepts any file type, generates a random filename, and stores the path in PostgreSQL database. Files are served directly via /uploads/<filename> URL.
```

**What to Do:**
1. Leave code field empty
2. Check **"NIST"** compliance
3. Click **"INITIATE THREAT ANALYSIS"**

**What to Say:**
> "This time, a file upload service with no file type validation. Let's see what the AI finds."

**What to Show:**
- Wait for analysis (10 seconds)
- Quickly scroll through results

**What to Say:**
> "As expected - unrestricted file upload, path traversal risks, arbitrary code execution, missing authentication. The system even suggests specific mitigations like implementing file type whitelisting and storing files outside the web root."

---

### **[2:40 - 3:00] CLOSING (20 seconds)**

**What to Say:**
> "This is the TECHGIUM Agentic Threat Modeling System - combining Data Flow Diagrams like OWASP pytm with multi-agent AI analysis. It automatically generates threat models, identifies vulnerabilities mapped to CWE and OWASP Top 10, and provides actionable remediation steps. Built with Pydantic AI, Mistral AI, and following MAESTRO security principles. Perfect for security teams, developers, and penetration testers."

**What to Show:**
- Scroll back to top showing the full dashboard
- Hover over "EXPORT REPORT" button
- End with a clean view of the tactical interface

---

## 🎯 KEY POINTS TO EMPHASIZE

1. **6 AI Agents** working in parallel (DFD Builder, Threat Generator, OWASP, Attack Tree, CWE, MAESTRO)
2. **Automatic DFD generation** from natural language (like OWASP pytm)
3. **Real vulnerabilities detected** with CWE and OWASP mappings
4. **Actionable remediation** steps for each vulnerability
5. **Professional tactical UI** with real-time analysis
6. **Multiple input methods** - description + code analysis

---

## 📋 BACKUP SCENARIOS (If Time Permits)

### Scenario 3: API with Rate Limiting Issues
```
REST API for a social media platform. Users can post messages, like posts, and follow other users. The API has no rate limiting. User authentication uses session cookies. The database uses raw SQL queries built from user input for search functionality.
```

### Scenario 4: IoT Device
```
Smart home thermostat with web interface. Connects to cloud backend via MQTT. Stores WiFi credentials in plaintext on device. Web interface accessible over HTTP on local network. Firmware updates downloaded over HTTP without signature verification.
```

---

## 🎬 PRODUCTION TIPS

1. **Screen Resolution**: Set browser to 1920x1080 for best clarity
2. **Zoom Level**: 100% or 110% for readability
3. **Cursor Highlighting**: Use a cursor highlighter tool
4. **Speaking Pace**: Moderate and clear
5. **Background Music**: Tactical/tech ambient music at low volume
6. **Transitions**: Smooth scrolling, no sudden movements

---

## ⌨️ KEYBOARD SHORTCUTS DURING DEMO

- **Tab**: Navigate between form fields quickly
- **Ctrl + A**: Select all text when clearing fields
- **Enter**: Submit form (when focused on button)
- **Scroll Wheel**: Smooth scrolling through results

---

## 🚨 TROUBLESHOOTING

**If analysis takes too long:**
- The first analysis initializes Mistral AI (may take 20-30 seconds)
- Subsequent analyses are faster (10-15 seconds)

**If you see errors:**
- Check that MISTRAL_API_KEY is set in environment
- Ensure server is running on http://0.0.0.0:8000

**If UI looks different:**
- Hard refresh browser (Ctrl + Shift + R)
- Clear browser cache

---

## 📊 EXPECTED ANALYSIS TIME

- **DFD Building**: 3-5 seconds
- **Threat Generation**: 2-3 seconds
- **OWASP Analysis**: 5-10 seconds
- **Attack Tree + CWE + MAESTRO**: 5-10 seconds
- **Total**: 15-30 seconds per analysis

---

**GOOD LUCK WITH YOUR DEMO! 🎥🛡️**
