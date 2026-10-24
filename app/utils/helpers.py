import os


def allowed_file(filename, allowed_extensions):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in allowed_extensions


def format_file_size(size_bytes: int) -> str:
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 ** 2:
        return f"{size_bytes / 1024:.1f} KB"
    elif size_bytes < 1024 ** 3:
        return f"{size_bytes / 1024**2:.1f} MB"
    return f"{size_bytes / 1024**3:.1f} GB"


def severity_color(severity: str) -> str:
    return {
        'critical': '#ef4444',
        'high': '#f97316',
        'medium': '#eab308',
        'low': '#22c55e',
        'info': '#3b82f6',
    }.get(severity, '#6b7280')


def severity_badge_class(severity: str) -> str:
    return {
        'critical': 'badge-critical',
        'high': 'badge-high',
        'medium': 'badge-medium',
        'low': 'badge-low',
        'info': 'badge-info',
    }.get(severity, 'badge-secondary')
