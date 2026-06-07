# characterization/templatetags/matrix_helpers.py
from django import template

# This variable MUST be named exactly 'register'
register = template.Library()

@register.filter(name='get_dst_status')
def get_dst_status(matrix_data, args):
    if not matrix_data:
        return 'none'
    try:
        source, destination = args.split(',')
        return matrix_data.get(source, {}).get(destination, 'none')
    except (ValueError, AttributeError):
        return 'none'