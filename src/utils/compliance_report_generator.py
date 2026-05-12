"""
Compliance Report Generator

Generates comprehensive compliance reports in HTML format (can be printed to PDF)
"""
from datetime import datetime
from typing import List
from src.models.threats import ThreatModel, ComplianceCheck


def generate_compliance_html_report(threat_model: ThreatModel) -> str:
    """
    Generate a comprehensive HTML compliance report

    Args:
        threat_model: Complete threat model with compliance checks

    Returns:
        HTML string ready for rendering or PDF conversion
    """

    if not threat_model.compliance_checks:
        return "<html><body><h1>No compliance analysis performed</h1></body></html>"

    # Group checks by framework
    frameworks = {}
    for check in threat_model.compliance_checks:
        if check.framework not in frameworks:
            frameworks[check.framework] = []
        frameworks[check.framework].append(check)

    # Calculate statistics
    total_controls = len(threat_model.compliance_checks)
    compliant = sum(1 for c in threat_model.compliance_checks if c.status == "compliant")
    non_compliant = sum(1 for c in threat_model.compliance_checks if c.status == "non_compliant")
    partial = sum(1 for c in threat_model.compliance_checks if c.status == "partial")
    not_applicable = sum(1 for c in threat_model.compliance_checks if c.status == "not_applicable")

    compliance_percentage = round((compliant / total_controls) * 100, 1) if total_controls > 0 else 0

    critical_gaps = [c for c in threat_model.compliance_checks if c.priority == "critical" and c.status == "non_compliant"]
    high_gaps = [c for c in threat_model.compliance_checks if c.priority == "high" and c.status == "non_compliant"]

    # Build HTML
    html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Compliance Report - {datetime.now().strftime('%Y-%m-%d')}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
            padding: 20px;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 40px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}

        .header {{
            border-bottom: 4px solid #2563eb;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }}

        .header h1 {{
            color: #1e40af;
            font-size: 32px;
            margin-bottom: 10px;
        }}

        .header .meta {{
            color: #6b7280;
            font-size: 14px;
        }}

        .executive-summary {{
            background: #eff6ff;
            border-left: 4px solid #2563eb;
            padding: 20px;
            margin-bottom: 30px;
        }}

        .executive-summary h2 {{
            color: #1e40af;
            font-size: 20px;
            margin-bottom: 15px;
        }}

        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}

        .stat-card {{
            background: white;
            border: 2px solid #e5e7eb;
            border-radius: 8px;
            padding: 20px;
            text-align: center;
        }}

        .stat-card.compliant {{
            border-color: #10b981;
            background: #f0fdf4;
        }}

        .stat-card.non-compliant {{
            border-color: #ef4444;
            background: #fef2f2;
        }}

        .stat-card.partial {{
            border-color: #f59e0b;
            background: #fffbeb;
        }}

        .stat-value {{
            font-size: 36px;
            font-weight: bold;
            color: #1f2937;
        }}

        .stat-label {{
            font-size: 14px;
            color: #6b7280;
            text-transform: uppercase;
            margin-top: 5px;
        }}

        .framework-section {{
            margin-bottom: 40px;
            page-break-inside: avoid;
        }}

        .framework-header {{
            background: #1e40af;
            color: white;
            padding: 15px 20px;
            border-radius: 8px 8px 0 0;
            font-size: 20px;
            font-weight: bold;
        }}

        .controls-list {{
            border: 2px solid #e5e7eb;
            border-top: none;
            border-radius: 0 0 8px 8px;
        }}

        .control {{
            padding: 20px;
            border-bottom: 1px solid #e5e7eb;
        }}

        .control:last-child {{
            border-bottom: none;
        }}

        .control-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }}

        .control-id {{
            font-weight: bold;
            color: #1e40af;
            font-size: 16px;
        }}

        .control-name {{
            color: #4b5563;
            margin-left: 10px;
        }}

        .status-badge {{
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: bold;
            text-transform: uppercase;
        }}

        .status-badge.compliant {{
            background: #d1fae5;
            color: #065f46;
        }}

        .status-badge.non_compliant {{
            background: #fee2e2;
            color: #991b1b;
        }}

        .status-badge.partial {{
            background: #fef3c7;
            color: #92400e;
        }}

        .status-badge.not_applicable {{
            background: #f3f4f6;
            color: #6b7280;
        }}

        .priority-badge {{
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: bold;
            text-transform: uppercase;
            margin-left: 10px;
        }}

        .priority-badge.critical {{
            background: #7f1d1d;
            color: white;
        }}

        .priority-badge.high {{
            background: #ef4444;
            color: white;
        }}

        .priority-badge.medium {{
            background: #f59e0b;
            color: white;
        }}

        .priority-badge.low {{
            background: #6b7280;
            color: white;
        }}

        .finding {{
            background: #f9fafb;
            padding: 15px;
            margin: 10px 0;
            border-left: 3px solid #6b7280;
            border-radius: 4px;
        }}

        .finding h4 {{
            color: #374151;
            font-size: 14px;
            margin-bottom: 8px;
        }}

        .finding p {{
            color: #6b7280;
            font-size: 14px;
        }}

        .evidence {{
            margin-top: 10px;
        }}

        .evidence-item {{
            color: #ef4444;
            font-size: 13px;
            padding: 5px 0;
            padding-left: 20px;
            position: relative;
        }}

        .evidence-item:before {{
            content: "!";
            position: absolute;
            left: 0;
        }}

        .remediation {{
            margin-top: 15px;
            background: #eff6ff;
            padding: 15px;
            border-radius: 4px;
            border-left: 3px solid #2563eb;
        }}

        .remediation h4 {{
            color: #1e40af;
            font-size: 14px;
            margin-bottom: 10px;
        }}

        .remediation-steps {{
            list-style: none;
            counter-reset: step-counter;
        }}

        .remediation-steps li {{
            counter-increment: step-counter;
            margin-bottom: 8px;
            padding-left: 30px;
            position: relative;
            font-size: 14px;
            color: #374151;
        }}

        .remediation-steps li:before {{
            content: counter(step-counter);
            position: absolute;
            left: 0;
            background: #2563eb;
            color: white;
            width: 20px;
            height: 20px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 12px;
            font-weight: bold;
        }}

        .code-fix {{
            margin-top: 15px;
            background: #1e293b;
            padding: 15px;
            border-radius: 4px;
            color: #e2e8f0;
            font-family: 'Courier New', monospace;
            font-size: 13px;
            overflow-x: auto;
        }}

        .code-fix h5 {{
            color: #60a5fa;
            margin-bottom: 10px;
            font-size: 14px;
        }}

        .code-fix pre {{
            margin: 10px 0;
            white-space: pre-wrap;
            word-wrap: break-word;
        }}

        .code-fix .label {{
            color: #94a3b8;
            font-size: 12px;
            margin-top: 10px;
            display: block;
        }}

        .effort {{
            margin-top: 10px;
            color: #6b7280;
            font-size: 13px;
            font-style: italic;
        }}

        .critical-gaps {{
            background: #fef2f2;
            border: 2px solid #ef4444;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 30px;
        }}

        .critical-gaps h2 {{
            color: #991b1b;
            margin-bottom: 15px;
        }}

        .footer {{
            margin-top: 40px;
            padding-top: 20px;
            border-top: 2px solid #e5e7eb;
            text-align: center;
            color: #6b7280;
            font-size: 12px;
        }}

        @media print {{
            body {{
                background: white;
                padding: 0;
            }}

            .container {{
                box-shadow: none;
                padding: 20px;
            }}

            .control {{
                page-break-inside: avoid;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Security Compliance Report</h1>
            <div class="meta">
                <strong>Generated:</strong> {datetime.now().strftime('%B %d, %Y at %H:%M UTC')}<br>
                <strong>Report ID:</strong> {threat_model.model_id}<br>
                <strong>System:</strong> {threat_model.asset_description[:200]}{"..." if len(threat_model.asset_description) > 200 else ""}
            </div>
        </div>

        <div class="executive-summary">
            <h2>Executive Summary</h2>
            <p>
                This compliance assessment analyzed <strong>{total_controls} security controls</strong> across
                <strong>{len(frameworks)} compliance frameworks</strong>. The overall compliance rate is
                <strong>{compliance_percentage}%</strong>, with <strong>{len(critical_gaps)} critical</strong> and
                <strong>{len(high_gaps)} high-priority</strong> gaps requiring immediate attention.
            </p>
        </div>

        <div class="stats-grid">
            <div class="stat-card compliant">
                <div class="stat-value">{compliant}</div>
                <div class="stat-label">Compliant</div>
            </div>
            <div class="stat-card non-compliant">
                <div class="stat-value">{non_compliant}</div>
                <div class="stat-label">Non-Compliant</div>
            </div>
            <div class="stat-card partial">
                <div class="stat-value">{partial}</div>
                <div class="stat-label">Partial</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{compliance_percentage}%</div>
                <div class="stat-label">Compliance Rate</div>
            </div>
        </div>
"""

    # Critical gaps section
    if critical_gaps:
        html += """
        <div class="critical-gaps">
            <h2>Critical Gaps Requiring Immediate Action</h2>
"""
        for gap in critical_gaps:
            html += f"""
            <div style="margin-bottom: 15px;">
                <strong>{gap.control_id}</strong> - {gap.control_name}<br>
                <span style="color: #6b7280; font-size: 14px;">{gap.finding}</span>
            </div>
"""
        html += """
        </div>
"""

    # Framework sections
    for framework, controls in frameworks.items():
        framework_compliant = sum(1 for c in controls if c.status == "compliant")
        framework_compliance = round((framework_compliant / len(controls)) * 100, 1) if controls else 0

        html += f"""
        <div class="framework-section">
            <div class="framework-header">
                {framework.replace('_', ' ')} - {framework_compliance}% Compliant ({framework_compliant}/{len(controls)} controls)
            </div>
            <div class="controls-list">
"""

        for control in controls:
            html += f"""
                <div class="control">
                    <div class="control-header">
                        <div>
                            <span class="control-id">{control.control_id}</span>
                            <span class="control-name">{control.control_name}</span>
                        </div>
                        <div>
                            <span class="status-badge {control.status}">{control.status.replace('_', ' ')}</span>
                            <span class="priority-badge {control.priority}">{control.priority}</span>
                        </div>
                    </div>
"""

            if control.finding:
                html += f"""
                    <div class="finding">
                        <h4>Gap Analysis:</h4>
                        <p>{control.finding}</p>
                    </div>
"""

            if control.evidence:
                html += """
                    <div class="evidence">
                        <h4 style="font-size: 14px; margin-bottom: 8px; color: #374151;">Evidence:</h4>
"""
                for evidence in control.evidence:
                    html += f"""
                        <div class="evidence-item">{evidence}</div>
"""
                html += """
                    </div>
"""

            if control.remediation_steps:
                html += """
                    <div class="remediation">
                        <h4>Remediation Steps:</h4>
                        <ol class="remediation-steps">
"""
                for step in control.remediation_steps:
                    html += f"""
                            <li>{step}</li>
"""
                html += """
                        </ol>
"""
                if control.estimated_effort:
                    html += f"""
                        <div class="effort">Estimated effort: {control.estimated_effort}</div>
"""
                html += """
                    </div>
"""

            if control.code_fixes:
                for code_fix in control.code_fixes:
                    html += f"""
                    <div class="code-fix">
                        <h5>Code Fix: {code_fix.explanation}</h5>
"""
                    if code_fix.file_path:
                        html += f"""
                        <span class="label">File: {code_fix.file_path}</span>
"""
                    if code_fix.vulnerable_code:
                        html += f"""
                        <span class="label">Before:</span>
                        <pre>{code_fix.vulnerable_code}</pre>
"""
                    html += f"""
                        <span class="label">After:</span>
                        <pre>{code_fix.fixed_code}</pre>
                    </div>
"""

            html += """
                </div>
"""

        html += """
            </div>
        </div>
"""

    # Footer
    html += f"""
        <div class="footer">
            <p>Generated by Techgium AI-Powered Threat Modeling System</p>
            <p>OWASP • CWE • MAESTRO • NIST AI RMF • ISO 27001</p>
            <p style="margin-top: 10px;">
                This report contains {total_controls} compliance controls across {len(frameworks)} frameworks.<br>
                Analysis completed in {round(threat_model.analysis_duration_seconds, 2)} seconds with {threat_model.confidence_score}% confidence.
            </p>
        </div>
    </div>
</body>
</html>
"""

    return html
