"""Punto de entrada para la interfaz local de Apate Core."""

from __future__ import annotations

from . import create_app


def main() -> None:
    app = create_app()
    app.run(host="127.0.0.1", debug=False)


if __name__ == "__main__":
    main()
