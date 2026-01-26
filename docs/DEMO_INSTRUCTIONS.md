# WiFi Guardian - Demo Instructions 🎬

## Quick Demo Options

You have **3 demo scripts** to show the system working:

### 1. Simple ML Demo (RECOMMENDED FOR HACKATHON) ⭐
**File**: `demo_ml_simple.py`
**Best for**: Showing ML models working with clear visual output

```bash
python demo_ml_simple.py
```

**What it shows**:
- ✅ Real trained ML models loading (84.40% accuracy)
- ✅ Random Forest + Isolation Forest predictions
- ✅ Normal vs suspicious traffic detection
- ✅ Beautiful CLI output with rich formatting
- ⏱️ **Runtime**: ~30 seconds
- 🎯 **Perfect for**: Quick, reliable demo

**Output**:
- Models loading with accuracy metrics
- Test 1: Normal traffic → Correctly classified
- Test 2: Suspicious traffic → Potential threat detected
- Summary of the ML pipeline

---

### 2. Full Agent Demo (Interactive)
**File**: `demo_agents.py`
**Best for**: Showing both Guardian and Sentinel agents

```bash
python demo_agents.py
```

**What it shows**:
- 🤖 Guardian Agent with ML models
- 🧠 Sentinel Agent with Mistral AI (LLM)
- 🔄 Inter-agent communication
- 📊 MITRE ATT&CK mapping
- ⏱️ **Runtime**: ~2-3 minutes (requires user input)
- ⚠️ **Note**: Requires Mistral API calls

**Requires**: Press Enter between scenarios

---

### 3. Automated Agent Demo
**File**: `demo_agents_auto.py`
**Best for**: Full automation without user input

```bash
python demo_agents_auto.py
```

**What it shows**:
- Same as demo_agents.py but automatic
- ⏱️ **Runtime**: ~2 minutes
- ⚠️ **Note**: Requires Mistral API (may timeout)

---

## Recommended Demo Flow for Hackathon

### Option A: Quick Demo (30 seconds)

1. Run the simple ML demo:
```bash
python demo_ml_simple.py
```

2. Show the dashboard:
- Open browser: http://localhost:8000/dashboard

3. Explain:
   - "These are REAL trained models (84.40% accuracy)"
   - "Trained on 125,000+ network attack samples"
   - "Random Forest + Isolation Forest ensemble"
   - "First agentic WiFi security system"

---

### Option B: Full Demo (3-5 minutes)

1. Start the backend:
```bash
python main.py &
```

2. Run ML demo:
```bash
python demo_ml_simple.py
```

3. Show dashboard:
   - Open: http://localhost:8000/dashboard
   - Show: System status, real-time capabilities

4. Show API docs:
   - Open: http://localhost:8000/docs
   - Highlight: REST endpoints, WebSocket

5. Explain architecture:
   - Guardian (ML) → Sentinel (LLM) → Response
   - Real models, real-time detection

---

## Demo Script for Judges

### Introduction (30 seconds)
"WiFi Guardian is the **first agentic WiFi security system** using Pydantic AI and Mistral AI."

**Key points**:
- Multi-agent architecture (Guardian + Sentinel)
- Real ML models trained on 125K+ samples
- 84.40% ensemble accuracy
- Explainable AI with MITRE ATT&CK mapping

### Live Demo (2 minutes)

**Run**: `python demo_ml_simple.py`

**Narrate while it runs**:
1. "Loading our trained models... (pause)"
2. "We have Random Forest with 76.56% accuracy..."
3. "And Isolation Forest with 79.64% accuracy..."
4. "Together they achieve 84.40% ensemble accuracy"
5. "Here's normal WiFi traffic being analyzed... (wait)"
6. "Correctly classified as Normal with high confidence"
7. "Now a suspicious packet with very high rate and entropy... (wait)"
8. "The models flag it as a potential threat"
9. "This would trigger our Sentinel agent for LLM analysis"

### Technical Deep Dive (1 minute, if asked)

**Point to code/logs**:
- "Models trained on NSL-KDD dataset on Kaggle"
- "Feature engineering maps WiFi packets to NSL-KDD format"
- "Predictions under 100ms for real-time detection"
- "Full pipeline: Capture → Extract → Predict → Analyze → Respond"

---

## Troubleshooting

### Demo Won't Run
```bash
# Install dependencies
pip install rich

# Check models exist
ls -la data/models/
```

### Port 8000 Already in Use
```bash
# Kill existing process
lsof -ti:8000 | xargs kill -9

# Restart
python main.py
```

### Slow Performance
- Use `demo_ml_simple.py` instead of full agent demos
- Skip Mistral API calls (just show ML)

---

## What Each Demo Shows

| Feature | ML Simple | Agent Full | Agent Auto |
|---------|-----------|------------|------------|
| ML Models | ✅ | ✅ | ✅ |
| Model Accuracy | ✅ | ✅ | ✅ |
| Guardian Agent | ❌ | ✅ | ✅ |
| Sentinel Agent | ❌ | ✅ | ✅ |
| Mistral AI | ❌ | ✅ | ✅ |
| MITRE Mapping | ❌ | ✅ | ✅ |
| User Input | ❌ | ✅ | ❌ |
| Runtime | 30s | 2-3min | 2min |
| Reliability | ⭐⭐⭐ | ⭐⭐ | ⭐⭐ |

**Recommendation**: Use `demo_ml_simple.py` for most reliable demo!

---

## Files Overview

### Demo Scripts
- `demo_ml_simple.py` - Simple ML demo (RECOMMENDED)
- `demo_agents.py` - Full agent demo (interactive)
- `demo_agents_auto.py` - Full agent demo (automatic)

### Main System
- `main.py` - Full system (backend + agents)
- Dashboard: http://localhost:8000/dashboard
- API: http://localhost:8000/docs

### Documentation
- `QUICK_DEMO_GUIDE.md` - Complete demo guide
- `ML_MODELS_INTEGRATION_SUCCESS.md` - ML integration details
- `BACKEND_TEST_RESULTS.md` - Testing report

---

## Emergency Backup

If live demo fails:

1. Show screenshots/recording
2. Walk through code and architecture
3. Show model training notebook (`train_ml_models.ipynb`)
4. Demonstrate API with curl:
```bash
curl http://localhost:8000/api/health
```

---

## Success Checklist

Before demo:
- [ ] Run `python demo_ml_simple.py` to test
- [ ] Backend running (`python main.py`)
- [ ] Dashboard accessible (http://localhost:8000/dashboard)
- [ ] Models loaded successfully (check logs)
- [ ] Rehearsed talking points

During demo:
- [ ] Speak clearly and confidently
- [ ] Highlight "First agentic WiFi security system"
- [ ] Emphasize "84.40% accuracy on real data"
- [ ] Show "Production-ready architecture"
- [ ] Mention "Pydantic AI + Mistral AI"

After demo:
- [ ] Answer technical questions
- [ ] Show code if asked
- [ ] Discuss future enhancements
- [ ] Thank judges!

---

## Quick Commands

```bash
# Simple ML demo (RECOMMENDED)
python demo_ml_simple.py

# Full agent demo
python demo_agents.py

# Start backend
python main.py

# Check health
curl http://localhost:8000/api/health

# View dashboard
open http://localhost:8000/dashboard

# Stop backend
pkill -f "python main.py"
```

---

**YOU'RE READY! GO WIN THAT HACKATHON! 🏆**
