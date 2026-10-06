"""Punto de entrada WSGI para el servidor de producción.

Gunicorn importa ``app`` y no ejecuta ``socketio.run()``. La instalación de
producción usa un único proceso threaded porque Flask-SocketIO con
``async_mode="threading"`` mantiene estado en memoria por proceso.
"""

from . import create_app

app = create_app()
