"""
Tool System for RegulAI Chat

This module provides a tool/function calling system that allows the LLM
to generate files and perform other actions through structured tool calls.
"""

import json
import io
import base64
from typing import Any, Dict, List, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum


class ToolResultType(Enum):
    """Type of result returned by a tool."""
    TEXT = "text"
    FILE = "file"
    ERROR = "error"


@dataclass
class ToolResult:
    """Result of executing a tool."""
    type: ToolResultType
    content: str = ""
    file_bytes: Optional[bytes] = None
    file_name: Optional[str] = None
    mime_type: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        result = {"type": self.type.value, "content": self.content}
        if self.file_name:
            result["file_name"] = self.file_name
        if self.mime_type:
            result["mime_type"] = self.mime_type
        return result


@dataclass
class Tool:
    """Definition of a tool that the LLM can use."""
    name: str
    description: str
    parameters: Dict[str, Any]  # JSON Schema for parameters
    handler: Callable[..., ToolResult]

    def to_openai_format(self) -> Dict[str, Any]:
        """Convert to OpenAI function calling format."""
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters
            }
        }

    def to_anthropic_format(self) -> Dict[str, Any]:
        """Convert to Anthropic tool use format."""
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": self.parameters
        }


# ============== Tool Implementations ==============

def create_document(title: str, content: str, format: str = "docx") -> ToolResult:
    """
    Create a document file (Word or PDF).

    Args:
        title: Document title
        content: Document content (can include markdown-style formatting)
        format: Output format - 'docx' or 'pdf'
    """
    try:
        if format.lower() == "docx":
            return _create_docx(title, content)
        elif format.lower() == "pdf":
            return _create_pdf(title, content)
        else:
            return ToolResult(
                type=ToolResultType.ERROR,
                content=f"Unsupported format: {format}. Use 'docx' or 'pdf'."
            )
    except Exception as e:
        return ToolResult(
            type=ToolResultType.ERROR,
            content=f"Error creating document: {str(e)}"
        )


def _create_docx(title: str, content: str) -> ToolResult:
    """Create a Word document."""
    from docx import Document
    from docx.shared import Inches, Pt
    from docx.enum.text import WD_ALIGN_PARAGRAPH

    doc = Document()

    # Add title
    title_para = doc.add_heading(title, 0)
    title_para.alignment = WD_ALIGN_PARAGRAPH.CENTER

    # Process content - handle basic markdown
    lines = content.split('\n')
    for line in lines:
        line = line.strip()
        if not line:
            doc.add_paragraph()
        elif line.startswith('# '):
            doc.add_heading(line[2:], 1)
        elif line.startswith('## '):
            doc.add_heading(line[3:], 2)
        elif line.startswith('### '):
            doc.add_heading(line[4:], 3)
        elif line.startswith('- ') or line.startswith('* '):
            doc.add_paragraph(line[2:], style='List Bullet')
        elif line[0:1].isdigit() and '. ' in line[:4]:
            doc.add_paragraph(line.split('. ', 1)[1], style='List Number')
        else:
            doc.add_paragraph(line)

    # Save to bytes
    buffer = io.BytesIO()
    doc.save(buffer)
    buffer.seek(0)

    # Generate filename
    safe_title = "".join(c for c in title if c.isalnum() or c in (' ', '-', '_')).strip()
    safe_title = safe_title[:50] if safe_title else "document"
    filename = f"{safe_title}.docx"

    return ToolResult(
        type=ToolResultType.FILE,
        content=f"Document '{title}' created successfully.",
        file_bytes=buffer.getvalue(),
        file_name=filename,
        mime_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    )


def _create_pdf(title: str, content: str) -> ToolResult:
    """Create a PDF document."""
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
        from reportlab.lib.enums import TA_CENTER
    except ImportError:
        return ToolResult(
            type=ToolResultType.ERROR,
            content="PDF generation not available. Please install reportlab: pip install reportlab"
        )

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()

    # Custom title style
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=18,
        alignment=TA_CENTER,
        spaceAfter=30
    )

    story = []

    # Add title
    story.append(Paragraph(title, title_style))
    story.append(Spacer(1, 12))

    # Process content
    lines = content.split('\n')
    for line in lines:
        line = line.strip()
        if not line:
            story.append(Spacer(1, 12))
        elif line.startswith('# '):
            story.append(Paragraph(line[2:], styles['Heading1']))
        elif line.startswith('## '):
            story.append(Paragraph(line[3:], styles['Heading2']))
        elif line.startswith('### '):
            story.append(Paragraph(line[4:], styles['Heading3']))
        elif line.startswith('- ') or line.startswith('* '):
            story.append(Paragraph(f"• {line[2:]}", styles['Normal']))
        else:
            story.append(Paragraph(line, styles['Normal']))

    doc.build(story)
    buffer.seek(0)

    safe_title = "".join(c for c in title if c.isalnum() or c in (' ', '-', '_')).strip()
    safe_title = safe_title[:50] if safe_title else "document"
    filename = f"{safe_title}.pdf"

    return ToolResult(
        type=ToolResultType.FILE,
        content=f"PDF '{title}' created successfully.",
        file_bytes=buffer.getvalue(),
        file_name=filename,
        mime_type="application/pdf"
    )


def create_spreadsheet(title: str, data: List[List[Any]], headers: Optional[List[str]] = None, format: str = "xlsx") -> ToolResult:
    """
    Create a spreadsheet file (Excel or CSV).

    Args:
        title: Spreadsheet title (used for filename and sheet name)
        data: 2D array of data (list of rows)
        headers: Optional column headers
        format: Output format - 'xlsx' or 'csv'
    """
    try:
        if format.lower() == "xlsx":
            return _create_xlsx(title, data, headers)
        elif format.lower() == "csv":
            return _create_csv(title, data, headers)
        else:
            return ToolResult(
                type=ToolResultType.ERROR,
                content=f"Unsupported format: {format}. Use 'xlsx' or 'csv'."
            )
    except Exception as e:
        return ToolResult(
            type=ToolResultType.ERROR,
            content=f"Error creating spreadsheet: {str(e)}"
        )


def _create_xlsx(title: str, data: List[List[Any]], headers: Optional[List[str]] = None) -> ToolResult:
    """Create an Excel spreadsheet."""
    from openpyxl import Workbook
    from openpyxl.styles import Font, PatternFill, Alignment

    wb = Workbook()
    ws = wb.active
    ws.title = title[:31]  # Excel sheet name limit

    # Style for headers
    header_font = Font(bold=True)
    header_fill = PatternFill(start_color="366092", end_color="366092", fill_type="solid")
    header_font_white = Font(bold=True, color="FFFFFF")

    row_offset = 1

    # Add headers if provided
    if headers:
        for col, header in enumerate(headers, 1):
            cell = ws.cell(row=1, column=col, value=header)
            cell.font = header_font_white
            cell.fill = header_fill
            cell.alignment = Alignment(horizontal='center')
        row_offset = 2

    # Add data
    for row_idx, row_data in enumerate(data, row_offset):
        for col_idx, value in enumerate(row_data, 1):
            ws.cell(row=row_idx, column=col_idx, value=value)

    # Auto-adjust column widths
    for column in ws.columns:
        max_length = 0
        column_letter = column[0].column_letter
        for cell in column:
            try:
                if len(str(cell.value)) > max_length:
                    max_length = len(str(cell.value))
            except:
                pass
        adjusted_width = min(max_length + 2, 50)
        ws.column_dimensions[column_letter].width = adjusted_width

    buffer = io.BytesIO()
    wb.save(buffer)
    buffer.seek(0)

    safe_title = "".join(c for c in title if c.isalnum() or c in (' ', '-', '_')).strip()
    safe_title = safe_title[:50] if safe_title else "spreadsheet"
    filename = f"{safe_title}.xlsx"

    return ToolResult(
        type=ToolResultType.FILE,
        content=f"Spreadsheet '{title}' created with {len(data)} rows.",
        file_bytes=buffer.getvalue(),
        file_name=filename,
        mime_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )


def _create_csv(title: str, data: List[List[Any]], headers: Optional[List[str]] = None) -> ToolResult:
    """Create a CSV file."""
    import csv

    buffer = io.StringIO()
    writer = csv.writer(buffer)

    if headers:
        writer.writerow(headers)

    for row in data:
        writer.writerow(row)

    content = buffer.getvalue()

    safe_title = "".join(c for c in title if c.isalnum() or c in (' ', '-', '_')).strip()
    safe_title = safe_title[:50] if safe_title else "data"
    filename = f"{safe_title}.csv"

    return ToolResult(
        type=ToolResultType.FILE,
        content=f"CSV '{title}' created with {len(data)} rows.",
        file_bytes=content.encode('utf-8'),
        file_name=filename,
        mime_type="text/csv"
    )


def create_code_file(filename: str, code: str, language: str = "python") -> ToolResult:
    """
    Create a code/script file.

    Args:
        filename: Name for the file (extension will be added if missing)
        code: The code content
        language: Programming language (python, javascript, html, css, sql, etc.)
    """
    LANG_EXTENSIONS = {
        'python': '.py',
        'javascript': '.js',
        'typescript': '.ts',
        'html': '.html',
        'css': '.css',
        'sql': '.sql',
        'json': '.json',
        'yaml': '.yaml',
        'xml': '.xml',
        'markdown': '.md',
        'bash': '.sh',
        'shell': '.sh',
    }

    ext = LANG_EXTENSIONS.get(language.lower(), '.txt')

    # Add extension if not present
    if not any(filename.endswith(e) for e in LANG_EXTENSIONS.values()):
        filename = filename + ext

    MIME_TYPES = {
        '.py': 'text/x-python',
        '.js': 'application/javascript',
        '.ts': 'application/typescript',
        '.html': 'text/html',
        '.css': 'text/css',
        '.sql': 'text/plain',
        '.json': 'application/json',
        '.yaml': 'text/yaml',
        '.xml': 'application/xml',
        '.md': 'text/markdown',
        '.sh': 'text/x-shellscript',
        '.txt': 'text/plain',
    }

    file_ext = '.' + filename.rsplit('.', 1)[-1] if '.' in filename else '.txt'
    mime_type = MIME_TYPES.get(file_ext, 'text/plain')

    return ToolResult(
        type=ToolResultType.FILE,
        content=f"Code file '{filename}' created.",
        file_bytes=code.encode('utf-8'),
        file_name=filename,
        mime_type=mime_type
    )


# ============== Chart Creation ==============

def create_chart(
    title: str,
    chart_type: str,
    labels: List[str],
    datasets: List[Dict[str, Any]],
    x_label: str = "",
    y_label: str = ""
) -> ToolResult:
    """
    Create a chart/graph as a PNG image.

    Args:
        title: Chart title
        chart_type: Type of chart - 'bar', 'line', 'pie', 'scatter'
        labels: X-axis labels or pie slice labels
        datasets: List of datasets, each with 'label' and 'data' keys
        x_label: Label for X axis
        y_label: Label for Y axis
    """
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        import numpy as np
    except ImportError:
        return ToolResult(
            type=ToolResultType.ERROR,
            content="Chart generation not available. Please install matplotlib."
        )

    try:
        fig, ax = plt.subplots(figsize=(10, 6))

        colors = ['#4e79a7', '#f28e2b', '#e15759', '#76b7b2', '#59a14f',
                  '#edc948', '#b07aa1', '#ff9da7', '#9c755f', '#bab0ac']

        if chart_type == 'pie':
            if datasets and len(datasets) > 0:
                data = datasets[0].get('data', [])
                ax.pie(data, labels=labels, autopct='%1.1f%%', colors=colors[:len(data)])
            ax.set_title(title, fontsize=14, fontweight='bold')

        elif chart_type == 'bar':
            x = np.arange(len(labels))
            width = 0.8 / len(datasets) if datasets else 0.8

            for i, dataset in enumerate(datasets):
                offset = (i - len(datasets)/2 + 0.5) * width
                bars = ax.bar(x + offset, dataset.get('data', []), width,
                             label=dataset.get('label', f'Series {i+1}'),
                             color=colors[i % len(colors)])

            ax.set_xticks(x)
            ax.set_xticklabels(labels)
            ax.set_title(title, fontsize=14, fontweight='bold')
            if x_label:
                ax.set_xlabel(x_label)
            if y_label:
                ax.set_ylabel(y_label)
            if len(datasets) > 1:
                ax.legend()

        elif chart_type == 'line':
            for i, dataset in enumerate(datasets):
                ax.plot(labels, dataset.get('data', []),
                       label=dataset.get('label', f'Series {i+1}'),
                       color=colors[i % len(colors)], marker='o')

            ax.set_title(title, fontsize=14, fontweight='bold')
            if x_label:
                ax.set_xlabel(x_label)
            if y_label:
                ax.set_ylabel(y_label)
            if len(datasets) > 1:
                ax.legend()
            ax.grid(True, alpha=0.3)

        elif chart_type == 'scatter':
            for i, dataset in enumerate(datasets):
                data = dataset.get('data', [])
                if data and isinstance(data[0], (list, tuple)):
                    x_vals = [p[0] for p in data]
                    y_vals = [p[1] for p in data]
                else:
                    x_vals = list(range(len(data)))
                    y_vals = data
                ax.scatter(x_vals, y_vals,
                          label=dataset.get('label', f'Series {i+1}'),
                          color=colors[i % len(colors)], alpha=0.7)

            ax.set_title(title, fontsize=14, fontweight='bold')
            if x_label:
                ax.set_xlabel(x_label)
            if y_label:
                ax.set_ylabel(y_label)
            if len(datasets) > 1:
                ax.legend()
            ax.grid(True, alpha=0.3)
        else:
            return ToolResult(
                type=ToolResultType.ERROR,
                content=f"Unknown chart type: {chart_type}. Use 'bar', 'line', 'pie', or 'scatter'."
            )

        plt.tight_layout()

        buffer = io.BytesIO()
        plt.savefig(buffer, format='png', dpi=150, bbox_inches='tight')
        buffer.seek(0)
        plt.close(fig)

        safe_title = "".join(c for c in title if c.isalnum() or c in (' ', '-', '_')).strip()
        safe_title = safe_title[:50] if safe_title else "chart"
        filename = f"{safe_title}.png"

        return ToolResult(
            type=ToolResultType.FILE,
            content=f"Chart '{title}' created successfully.",
            file_bytes=buffer.getvalue(),
            file_name=filename,
            mime_type="image/png"
        )

    except Exception as e:
        return ToolResult(
            type=ToolResultType.ERROR,
            content=f"Error creating chart: {str(e)}"
        )


# ============== Data Analysis ==============

def analyze_data(
    data: List[List[Any]],
    headers: Optional[List[str]] = None,
    analysis_type: str = "summary"
) -> ToolResult:
    """
    Analyze tabular data and return statistics.

    Args:
        data: 2D array of data
        headers: Column headers
        analysis_type: Type of analysis - 'summary', 'correlation', 'distribution'
    """
    try:
        if not data or len(data) == 0:
            return ToolResult(
                type=ToolResultType.ERROR,
                content="No data provided for analysis."
            )

        # Convert to numeric where possible
        numeric_columns = {}
        num_cols = len(data[0]) if data else 0

        for col_idx in range(num_cols):
            col_data = []
            for row in data:
                if col_idx < len(row):
                    try:
                        val = float(row[col_idx])
                        col_data.append(val)
                    except (ValueError, TypeError):
                        pass
            if col_data:
                col_name = headers[col_idx] if headers and col_idx < len(headers) else f"Column {col_idx + 1}"
                numeric_columns[col_name] = col_data

        if not numeric_columns:
            return ToolResult(
                type=ToolResultType.TEXT,
                content=f"Data has {len(data)} rows and {num_cols} columns, but no numeric columns found for statistical analysis."
            )

        result_lines = [f"# Data Analysis Report", f""]
        result_lines.append(f"**Dataset:** {len(data)} rows, {num_cols} columns")
        result_lines.append(f"**Numeric columns:** {len(numeric_columns)}")
        result_lines.append("")

        if analysis_type in ["summary", "all"]:
            result_lines.append("## Summary Statistics")
            result_lines.append("")

            for col_name, values in numeric_columns.items():
                n = len(values)
                mean_val = sum(values) / n
                sorted_vals = sorted(values)
                median_val = sorted_vals[n // 2] if n % 2 == 1 else (sorted_vals[n//2 - 1] + sorted_vals[n//2]) / 2
                min_val = min(values)
                max_val = max(values)
                variance = sum((x - mean_val) ** 2 for x in values) / n
                std_val = variance ** 0.5

                result_lines.append(f"### {col_name}")
                result_lines.append(f"- Count: {n}")
                result_lines.append(f"- Mean: {mean_val:.2f}")
                result_lines.append(f"- Median: {median_val:.2f}")
                result_lines.append(f"- Std Dev: {std_val:.2f}")
                result_lines.append(f"- Min: {min_val:.2f}")
                result_lines.append(f"- Max: {max_val:.2f}")
                result_lines.append("")

        return ToolResult(
            type=ToolResultType.TEXT,
            content="\n".join(result_lines)
        )

    except Exception as e:
        return ToolResult(
            type=ToolResultType.ERROR,
            content=f"Error analyzing data: {str(e)}"
        )


# ============== Presentation Creation ==============

def create_presentation(
    title: str,
    slides: List[Dict[str, Any]]
) -> ToolResult:
    """
    Create a PowerPoint presentation.

    Args:
        title: Presentation title (used for filename and title slide)
        slides: List of slide definitions, each with 'title', 'content', and optional 'layout'
    """
    try:
        from pptx import Presentation
        from pptx.util import Inches, Pt
        from pptx.enum.text import PP_ALIGN
    except ImportError:
        return ToolResult(
            type=ToolResultType.ERROR,
            content="Presentation generation not available. Please install python-pptx."
        )

    try:
        prs = Presentation()
        prs.slide_width = Inches(13.333)
        prs.slide_height = Inches(7.5)

        # Title slide
        title_slide_layout = prs.slide_layouts[6]  # Blank
        slide = prs.slides.add_slide(title_slide_layout)

        # Add title text box
        left = Inches(0.5)
        top = Inches(2.5)
        width = Inches(12.333)
        height = Inches(2)
        txBox = slide.shapes.add_textbox(left, top, width, height)
        tf = txBox.text_frame
        p = tf.paragraphs[0]
        p.text = title
        p.font.size = Pt(44)
        p.font.bold = True
        p.alignment = PP_ALIGN.CENTER

        # Content slides
        for slide_def in slides:
            slide_layout = prs.slide_layouts[6]  # Blank
            slide = prs.slides.add_slide(slide_layout)

            # Slide title
            slide_title = slide_def.get('title', '')
            if slide_title:
                left = Inches(0.5)
                top = Inches(0.3)
                width = Inches(12.333)
                height = Inches(1)
                txBox = slide.shapes.add_textbox(left, top, width, height)
                tf = txBox.text_frame
                p = tf.paragraphs[0]
                p.text = slide_title
                p.font.size = Pt(32)
                p.font.bold = True

            # Slide content
            content = slide_def.get('content', '')
            if content:
                left = Inches(0.5)
                top = Inches(1.5)
                width = Inches(12.333)
                height = Inches(5.5)
                txBox = slide.shapes.add_textbox(left, top, width, height)
                tf = txBox.text_frame
                tf.word_wrap = True

                # Handle bullet points
                lines = content.split('\n')
                for i, line in enumerate(lines):
                    if i == 0:
                        p = tf.paragraphs[0]
                    else:
                        p = tf.add_paragraph()

                    # Handle bullet points
                    if line.strip().startswith('- ') or line.strip().startswith('* '):
                        p.text = '• ' + line.strip()[2:]
                        p.level = 0
                    elif line.strip().startswith('  - ') or line.strip().startswith('  * '):
                        p.text = '  • ' + line.strip()[4:]
                        p.level = 1
                    else:
                        p.text = line

                    p.font.size = Pt(18)

        buffer = io.BytesIO()
        prs.save(buffer)
        buffer.seek(0)

        safe_title = "".join(c for c in title if c.isalnum() or c in (' ', '-', '_')).strip()
        safe_title = safe_title[:50] if safe_title else "presentation"
        filename = f"{safe_title}.pptx"

        return ToolResult(
            type=ToolResultType.FILE,
            content=f"Presentation '{title}' created with {len(slides) + 1} slides.",
            file_bytes=buffer.getvalue(),
            file_name=filename,
            mime_type="application/vnd.openxmlformats-officedocument.presentationml.presentation"
        )

    except Exception as e:
        return ToolResult(
            type=ToolResultType.ERROR,
            content=f"Error creating presentation: {str(e)}"
        )


# ============== Utility Tools ==============

def get_current_datetime(timezone: str = "UTC", format: str = "full") -> ToolResult:
    """
    Get the current date and time.

    Args:
        timezone: Timezone name (e.g., 'UTC', 'Europe/Madrid', 'America/New_York')
        format: Output format - 'full', 'date', 'time', 'iso'
    """
    from datetime import datetime
    try:
        import pytz
        tz = pytz.timezone(timezone)
        now = datetime.now(tz)
    except:
        from datetime import timezone as tz_module
        now = datetime.now(tz_module.utc)
        timezone = "UTC"

    if format == "date":
        result = now.strftime("%Y-%m-%d")
    elif format == "time":
        result = now.strftime("%H:%M:%S")
    elif format == "iso":
        result = now.isoformat()
    else:  # full
        result = now.strftime("%A, %B %d, %Y at %H:%M:%S %Z")

    return ToolResult(
        type=ToolResultType.TEXT,
        content=f"Current date/time ({timezone}): {result}"
    )


def calculate(expression: str) -> ToolResult:
    """
    Evaluate a mathematical expression safely.

    Args:
        expression: Mathematical expression to evaluate (e.g., "2 + 2", "sqrt(16)", "sin(pi/2)")
    """
    import math
    import re

    # Allowed functions and constants
    allowed_names = {
        'abs': abs, 'round': round, 'min': min, 'max': max,
        'sum': sum, 'pow': pow, 'len': len,
        'sqrt': math.sqrt, 'sin': math.sin, 'cos': math.cos, 'tan': math.tan,
        'log': math.log, 'log10': math.log10, 'log2': math.log2,
        'exp': math.exp, 'floor': math.floor, 'ceil': math.ceil,
        'pi': math.pi, 'e': math.e,
        'asin': math.asin, 'acos': math.acos, 'atan': math.atan,
        'sinh': math.sinh, 'cosh': math.cosh, 'tanh': math.tanh,
        'degrees': math.degrees, 'radians': math.radians,
    }

    # Security: only allow safe characters
    if not re.match(r'^[\d\s\+\-\*\/\%\(\)\.\,\w]+$', expression):
        return ToolResult(
            type=ToolResultType.ERROR,
            content="Invalid characters in expression. Only numbers, operators (+,-,*,/,%), parentheses, and math functions are allowed."
        )

    try:
        # Evaluate safely
        result = eval(expression, {"__builtins__": {}}, allowed_names)

        # Format result
        if isinstance(result, float):
            if result == int(result):
                result = int(result)
            else:
                result = round(result, 10)

        return ToolResult(
            type=ToolResultType.TEXT,
            content=f"{expression} = {result}"
        )
    except Exception as e:
        return ToolResult(
            type=ToolResultType.ERROR,
            content=f"Error evaluating expression: {str(e)}"
        )


def web_search(query: str, num_results: int = 5) -> ToolResult:
    """
    Search the web for information using DuckDuckGo.

    Args:
        query: Search query
        num_results: Number of results to return (max 10)
    """
    import requests
    import re

    num_results = min(num_results, 10)

    try:
        # Use DuckDuckGo HTML search (no API key needed)
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }

        response = requests.get(
            'https://html.duckduckgo.com/html/',
            params={'q': query},
            headers=headers,
            timeout=10
        )
        response.raise_for_status()

        # Parse results (simple regex extraction)
        html = response.text

        # Find result links and snippets
        results = []
        pattern = r'<a[^>]+class="result__a"[^>]+href="([^"]+)"[^>]*>([^<]+)</a>'
        snippet_pattern = r'<a[^>]+class="result__snippet"[^>]*>([^<]+)</a>'

        links = re.findall(pattern, html)
        snippets = re.findall(snippet_pattern, html)

        for i, (url, title) in enumerate(links[:num_results]):
            snippet = snippets[i] if i < len(snippets) else ""
            # Clean up the text
            title = re.sub(r'<[^>]+>', '', title).strip()
            snippet = re.sub(r'<[^>]+>', '', snippet).strip()
            results.append({
                'title': title,
                'url': url,
                'snippet': snippet
            })

        if not results:
            return ToolResult(
                type=ToolResultType.TEXT,
                content=f"No results found for: {query}"
            )

        # Format results
        output = [f"# Search Results for: {query}\n"]
        for i, r in enumerate(results, 1):
            output.append(f"## {i}. {r['title']}")
            output.append(f"URL: {r['url']}")
            if r['snippet']:
                output.append(f"{r['snippet']}")
            output.append("")

        return ToolResult(
            type=ToolResultType.TEXT,
            content="\n".join(output)
        )

    except requests.Timeout:
        return ToolResult(
            type=ToolResultType.ERROR,
            content="Search timed out. Please try again."
        )
    except Exception as e:
        return ToolResult(
            type=ToolResultType.ERROR,
            content=f"Error performing search: {str(e)}"
        )


# ============== Tool Registry ==============

AVAILABLE_TOOLS: Dict[str, Tool] = {}


def register_tool(tool: Tool):
    """Register a tool in the global registry."""
    AVAILABLE_TOOLS[tool.name] = tool


def get_tool(name: str) -> Optional[Tool]:
    """Get a tool by name."""
    return AVAILABLE_TOOLS.get(name)


def get_all_tools() -> List[Tool]:
    """Get all registered tools."""
    return list(AVAILABLE_TOOLS.values())


def get_tools_for_openai(enabled_tools: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    """Get tools in OpenAI function calling format, optionally filtered."""
    tools = AVAILABLE_TOOLS.values()
    if enabled_tools is not None:
        tools = [t for t in tools if t.name in enabled_tools]
    return [tool.to_openai_format() for tool in tools]


def get_tools_for_anthropic(enabled_tools: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    """Get tools in Anthropic tool use format, optionally filtered."""
    tools = AVAILABLE_TOOLS.values()
    if enabled_tools is not None:
        tools = [t for t in tools if t.name in enabled_tools]
    return [tool.to_anthropic_format() for tool in tools]


def get_enabled_tools_for_company(company) -> List[str]:
    """Get list of enabled tool names for a company."""
    try:
        if hasattr(company, 'tool_config'):
            return company.tool_config.get_enabled_tools()
    except:
        pass
    # Default: all tools enabled except web_search
    return [name for name in AVAILABLE_TOOLS.keys() if name != 'web_search']


def execute_tool(name: str, arguments: Dict[str, Any]) -> ToolResult:
    """Execute a tool by name with the given arguments."""
    tool = get_tool(name)
    if not tool:
        return ToolResult(
            type=ToolResultType.ERROR,
            content=f"Unknown tool: {name}"
        )

    try:
        return tool.handler(**arguments)
    except TypeError as e:
        return ToolResult(
            type=ToolResultType.ERROR,
            content=f"Invalid arguments for tool {name}: {str(e)}"
        )
    except Exception as e:
        return ToolResult(
            type=ToolResultType.ERROR,
            content=f"Error executing tool {name}: {str(e)}"
        )


# ============== Register Default Tools ==============

# Document creation tool
register_tool(Tool(
    name="create_document",
    description="Create a document file (Word DOCX or PDF). Use this when the user asks for a document, report, letter, memo, or any formatted text document.",
    parameters={
        "type": "object",
        "properties": {
            "title": {
                "type": "string",
                "description": "The title of the document"
            },
            "content": {
                "type": "string",
                "description": "The document content. Can use markdown formatting: # for headings, - for bullet points, numbered lists, etc."
            },
            "format": {
                "type": "string",
                "enum": ["docx", "pdf"],
                "description": "Output format: 'docx' for Microsoft Word, 'pdf' for PDF",
                "default": "docx"
            }
        },
        "required": ["title", "content"]
    },
    handler=create_document
))

# Spreadsheet creation tool
register_tool(Tool(
    name="create_spreadsheet",
    description="Create a spreadsheet file (Excel XLSX or CSV). Use this when the user asks for a spreadsheet, table, data export, or any tabular data.",
    parameters={
        "type": "object",
        "properties": {
            "title": {
                "type": "string",
                "description": "The title/name of the spreadsheet"
            },
            "headers": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Column headers for the spreadsheet"
            },
            "data": {
                "type": "array",
                "items": {
                    "type": "array",
                    "items": {}
                },
                "description": "2D array of data rows. Each row is an array of cell values."
            },
            "format": {
                "type": "string",
                "enum": ["xlsx", "csv"],
                "description": "Output format: 'xlsx' for Excel, 'csv' for CSV",
                "default": "xlsx"
            }
        },
        "required": ["title", "data"]
    },
    handler=create_spreadsheet
))

# Code file creation tool
register_tool(Tool(
    name="create_code_file",
    description="Create a code or script file. Use this when the user asks for code, a script, configuration file, or any programming-related file.",
    parameters={
        "type": "object",
        "properties": {
            "filename": {
                "type": "string",
                "description": "Name for the file (e.g., 'script.py', 'config.json')"
            },
            "code": {
                "type": "string",
                "description": "The code/script content"
            },
            "language": {
                "type": "string",
                "enum": ["python", "javascript", "typescript", "html", "css", "sql", "json", "yaml", "xml", "markdown", "bash", "shell"],
                "description": "Programming language",
                "default": "python"
            }
        },
        "required": ["filename", "code"]
    },
    handler=create_code_file
))

# Chart creation tool
register_tool(Tool(
    name="create_chart",
    description="Create a chart or graph as a PNG image. Use this when the user asks for a chart, graph, visualization, or plot of data.",
    parameters={
        "type": "object",
        "properties": {
            "title": {
                "type": "string",
                "description": "Title of the chart"
            },
            "chart_type": {
                "type": "string",
                "enum": ["bar", "line", "pie", "scatter"],
                "description": "Type of chart: 'bar' for bar chart, 'line' for line chart, 'pie' for pie chart, 'scatter' for scatter plot"
            },
            "labels": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Labels for X-axis (bar/line) or slice names (pie)"
            },
            "datasets": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "label": {"type": "string", "description": "Name of this data series"},
                        "data": {"type": "array", "items": {"type": "number"}, "description": "Data values"}
                    }
                },
                "description": "Array of datasets to plot"
            },
            "x_label": {
                "type": "string",
                "description": "Label for the X axis"
            },
            "y_label": {
                "type": "string",
                "description": "Label for the Y axis"
            }
        },
        "required": ["title", "chart_type", "labels", "datasets"]
    },
    handler=create_chart
))

# Data analysis tool
register_tool(Tool(
    name="analyze_data",
    description="Analyze tabular data and return statistical summary. Use this when the user asks to analyze data, calculate statistics, or understand data patterns.",
    parameters={
        "type": "object",
        "properties": {
            "data": {
                "type": "array",
                "items": {"type": "array"},
                "description": "2D array of data (rows and columns)"
            },
            "headers": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Column headers/names"
            },
            "analysis_type": {
                "type": "string",
                "enum": ["summary", "correlation", "distribution", "all"],
                "description": "Type of analysis to perform",
                "default": "summary"
            }
        },
        "required": ["data"]
    },
    handler=analyze_data
))

# Presentation creation tool
register_tool(Tool(
    name="create_presentation",
    description="Create a PowerPoint presentation (PPTX). Use this when the user asks for a presentation, slides, or deck.",
    parameters={
        "type": "object",
        "properties": {
            "title": {
                "type": "string",
                "description": "Title of the presentation (shown on title slide)"
            },
            "slides": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "title": {"type": "string", "description": "Slide title"},
                        "content": {"type": "string", "description": "Slide content. Use '- ' for bullet points."}
                    }
                },
                "description": "Array of slide definitions"
            }
        },
        "required": ["title", "slides"]
    },
    handler=create_presentation
))

# Current date/time tool
register_tool(Tool(
    name="get_current_datetime",
    description="Get the current date and time. Use this when the user asks what time it is, today's date, or needs the current timestamp.",
    parameters={
        "type": "object",
        "properties": {
            "timezone": {
                "type": "string",
                "description": "Timezone (e.g., 'UTC', 'Europe/Madrid', 'America/New_York')",
                "default": "UTC"
            },
            "format": {
                "type": "string",
                "enum": ["full", "date", "time", "iso"],
                "description": "Output format",
                "default": "full"
            }
        },
        "required": []
    },
    handler=get_current_datetime
))

# Calculator tool
register_tool(Tool(
    name="calculate",
    description="Evaluate a mathematical expression. Use this for calculations, math operations, conversions, or when the user needs to compute something.",
    parameters={
        "type": "object",
        "properties": {
            "expression": {
                "type": "string",
                "description": "Mathematical expression to evaluate (e.g., '2 + 2', 'sqrt(16)', 'sin(pi/2)', '100 * 1.21')"
            }
        },
        "required": ["expression"]
    },
    handler=calculate
))

# Web search tool
register_tool(Tool(
    name="web_search",
    description="Search the web for current information. Use this when the user asks about recent events, needs to look up facts, or wants information you might not have.",
    parameters={
        "type": "object",
        "properties": {
            "query": {
                "type": "string",
                "description": "The search query"
            },
            "num_results": {
                "type": "integer",
                "description": "Number of results to return (1-10)",
                "default": 5
            }
        },
        "required": ["query"]
    },
    handler=web_search
))
