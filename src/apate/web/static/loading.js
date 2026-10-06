/* Feedback visual en acciones que de verdad tardan (Docker/WinRM/
   subprocess/red) -- ver docs/roadmap.md. Deliberadamente NO se aplica a
   todos los formularios de la app: solo a los marcados explicitamente con
   el atributo `data-slow-action` (crear/editar operacion, agregar
   escenario, vincular plugin, transiciones de estado, guardar reglas o CRUD
   del Catálogo son JSON/SQLite local -- milisegundos, no
   necesitan esto).

   Un unico listener delegado en `document` (registrado una sola vez, sin
   importar cuando se cargue este script respecto del resto del DOM --
   `submit` burbujea, no hace falta esperar a que cada <form> ya exista) en
   vez de buscar `form[data-slow-action]` y atar un listener por formulario
   en cada template -- el patron completo vive acá una sola vez, los
   templates solo agregan el atributo.

   `event.defaultPrevented` se respeta a proposito: si otro listener sobre
   el mismo 'submit' ya cancelo el envio antes de que este corra (dispara
   despues, en fase de bubbling, del listener compartido de confirmaciones
   de ui.js), no tiene sentido deshabilitar el boton para un envio que no va
   a ocurrir. base.html carga ui.js antes de este archivo a proposito para
   preservar ese orden también entre listeners delegados. */
(function () {
  document.addEventListener("submit", function (event) {
    if (event.defaultPrevented) {
      return;
    }
    var form = event.target;
    if (!(form instanceof HTMLFormElement) || !form.hasAttribute("data-slow-action")) {
      return;
    }
    var button = form.querySelector('button[type="submit"]');
    if (!button || button.disabled) {
      return;
    }
    var loadingText = button.getAttribute("data-loading-text") || "Procesando...";
    button.disabled = true;
    button.innerHTML = "";
    var spinner = document.createElement("span");
    spinner.className = "btn-spinner";
    button.appendChild(spinner);
    button.appendChild(document.createTextNode(loadingText));
  });
})();
