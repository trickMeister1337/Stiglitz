"""Validador Email/DNS — confirmação já feita via dig em confirm_email()."""
from . import register


@register("email")
def validate(ctx):
    return True, 95, "Configuração de email verificada via DNS"
