/* Comportamientos UI compartidos de APATE: progresivos y sin framework. */
(function () {
  const root = document.documentElement;
  const storedTheme = localStorage.getItem('apate-theme');
  const storedDensity = localStorage.getItem('apate-density');
  const storedPresentation = localStorage.getItem('apate-presentation');
  if (storedTheme === 'light') root.dataset.theme = 'light';
  if (storedDensity === 'compact') root.dataset.density = 'compact';
  if (storedPresentation === 'true') root.dataset.presentation = 'true';

  function refreshPreferenceLabels() {
    document.querySelectorAll('[data-theme-toggle]').forEach(function (button) {
      button.textContent = root.dataset.theme === 'light'
        ? (button.dataset.labelDark || 'Dark theme')
        : (button.dataset.labelLight || 'Light theme');
    });
    document.querySelectorAll('[data-density-toggle]').forEach(function (button) {
      button.textContent = root.dataset.density === 'compact'
        ? (button.dataset.labelComfortable || 'Comfortable view')
        : (button.dataset.labelCompact || 'Compact view');
    });
    document.querySelectorAll('[data-presentation-toggle]').forEach(function (button) {
      button.setAttribute('aria-pressed', String(root.dataset.presentation === 'true'));
    });
  }
  refreshPreferenceLabels();
  document.querySelectorAll('[data-theme-toggle]').forEach(function (button) {
    button.addEventListener('click', function () {
      root.dataset.theme = root.dataset.theme === 'light' ? 'dark' : 'light';
      localStorage.setItem('apate-theme', root.dataset.theme);
      refreshPreferenceLabels();
    });
  });
  document.querySelectorAll('[data-density-toggle]').forEach(function (button) {
    button.addEventListener('click', function () {
      root.dataset.density = root.dataset.density === 'compact' ? 'comfortable' : 'compact';
      localStorage.setItem('apate-density', root.dataset.density);
      refreshPreferenceLabels();
    });
  });
  document.querySelectorAll('[data-presentation-toggle]').forEach(function (button) {
    button.addEventListener('click', function () {
      const active = root.dataset.presentation !== 'true';
      root.dataset.presentation = active ? 'true' : 'false';
      localStorage.setItem('apate-presentation', String(active));
      refreshPreferenceLabels();
      const focusTarget = active
        ? document.querySelector('.presentation-exit')
        : document.querySelector('.sidebar [data-presentation-toggle]');
      if (focusTarget) focusTarget.focus({ preventScroll: true });
      if (active) window.scrollTo({ top: 0, behavior: 'auto' });
    });
  });

  const helpDialog = document.querySelector('[data-help-dialog]');
  document.querySelectorAll('[data-help-open]').forEach(function (button) {
    button.addEventListener('click', function () { helpDialog.showModal(); });
  });

  function relativeTime(date) {
    const seconds = Math.round((date.getTime() - Date.now()) / 1000);
    const units = [[31536000, 'year'], [2592000, 'month'], [86400, 'day'], [3600, 'hour'], [60, 'minute']];
    const formatter = new Intl.RelativeTimeFormat(root.lang || 'es', { numeric: 'auto' });
    for (const unit of units) {
      if (Math.abs(seconds) >= unit[0]) return formatter.format(Math.round(seconds / unit[0]), unit[1]);
    }
    return formatter.format(seconds, 'second');
  }
  document.querySelectorAll('time[data-local-time][datetime]').forEach(function (element) {
    const date = new Date(element.getAttribute('datetime'));
    if (Number.isNaN(date.getTime())) return;
    const absolute = new Intl.DateTimeFormat(root.lang || 'es', { dateStyle: 'medium', timeStyle: 'short' }).format(date);
    element.textContent = absolute + ' · ' + relativeTime(date);
    element.title = 'UTC: ' + date.toISOString().replace('T', ' ').replace('.000Z', 'Z');
  });

  const navToggle = document.querySelector('[data-nav-toggle]');
  const sidebarNav = document.getElementById('sidebar-navigation');
  if (navToggle && sidebarNav) {
    navToggle.addEventListener('click', function () {
      const expanded = navToggle.getAttribute('aria-expanded') === 'true';
      navToggle.setAttribute('aria-expanded', String(!expanded));
      sidebarNav.classList.toggle('mobile-open', !expanded);
    });
  }

  document.querySelectorAll('[data-flash-dismiss]').forEach(function (button) {
    button.addEventListener('click', function () {
      const flash = button.closest('.flash');
      if (flash) flash.remove();
    });
  });

  const confirmDialog = document.querySelector('[data-confirm-dialog]');
  let pendingForm = null;
  let pendingSubmitter = null;
  document.addEventListener('submit', function (event) {
    const form = event.target;
    const message = form.getAttribute('data-confirm');
    if (!message || form.dataset.confirmed === 'true') return;
    event.preventDefault();
    if (!confirmDialog || typeof confirmDialog.showModal !== 'function') {
      if (window.confirm(message)) {
        form.dataset.confirmed = 'true';
        form.requestSubmit(event.submitter || undefined);
      }
      return;
    }
    pendingForm = form;
    pendingSubmitter = event.submitter || null;
    confirmDialog.querySelector('[data-confirm-message]').textContent = message;
    const requiredName = form.getAttribute('data-confirm-name') || '';
    const wrap = confirmDialog.querySelector('[data-confirm-name-wrap]');
    const input = confirmDialog.querySelector('[data-confirm-name-input]');
    wrap.hidden = !requiredName;
    confirmDialog.querySelector('[data-confirm-name]').textContent = requiredName;
    input.value = '';
    confirmDialog.querySelector('[data-confirm-accept]').disabled = Boolean(requiredName);
    input.oninput = function () {
      confirmDialog.querySelector('[data-confirm-accept]').disabled = input.value.trim() !== requiredName;
    };
    confirmDialog.returnValue = 'cancel';
    confirmDialog.showModal();
  });
  if (confirmDialog) {
    confirmDialog.addEventListener('close', function () {
      if (confirmDialog.returnValue === 'confirm' && pendingForm) {
        pendingForm.dataset.confirmed = 'true';
        pendingForm.requestSubmit(pendingSubmitter || undefined);
      }
      pendingForm = null;
      pendingSubmitter = null;
    });
  }

  const commandDialog = document.querySelector('[data-command-dialog]');
  const commandSearch = document.querySelector('[data-command-search]');
  function openCommands() {
    if (!commandDialog || commandDialog.open) return;
    commandDialog.showModal();
    commandSearch.value = '';
    document.querySelectorAll('[data-command-item]').forEach(function (item) { item.hidden = false; });
    commandSearch.focus();
  }
  document.querySelectorAll('[data-command-open]').forEach(function (button) {
    button.addEventListener('click', openCommands);
  });
  if (commandSearch) commandSearch.addEventListener('input', function () {
    const query = commandSearch.value.trim().toLocaleLowerCase('es');
    document.querySelectorAll('[data-command-item]').forEach(function (item) {
      const searchable = item.textContent + ' ' + (item.dataset.commandKeywords || '');
      item.hidden = !searchable.toLocaleLowerCase('es').includes(query);
    });
  });
  let commandPrefix = false;
  let commandPrefixTimer = null;
  document.addEventListener('keydown', function (event) {
    const editing = /^(INPUT|TEXTAREA|SELECT)$/.test(event.target.tagName);
    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') {
      event.preventDefault();
      openCommands();
    } else if (!editing && event.key === '/') {
      event.preventDefault();
      openCommands();
    } else if (!editing && event.key.toLowerCase() === 'g') {
      commandPrefix = true;
      window.clearTimeout(commandPrefixTimer);
      commandPrefixTimer = window.setTimeout(function () { commandPrefix = false; }, 1200);
    } else if (!editing && commandPrefix && event.key.toLowerCase() === 'o') {
      window.location.href = '/operations/';
    } else if (!editing && commandPrefix && event.key.toLowerCase() === 't') {
      window.location.href = '/telemetry/';
    }
  });

  document.querySelectorAll('form[data-guard-unsaved]').forEach(function (form) {
    let dirty = false;
    const undoStack = [];
    const undoToolbar = document.createElement('div');
    undoToolbar.className = 'editor-undo-toolbar';
    const undoButton = document.createElement('button');
    undoButton.type = 'button';
    undoButton.className = 'small';
    undoButton.disabled = true;
    undoButton.textContent = form.dataset.undoLabel || 'Undo last edit';
    const undoStatus = document.createElement('span');
    undoStatus.className = 'muted';
    undoStatus.setAttribute('aria-live', 'polite');
    undoStatus.textContent = form.dataset.undoDescription || 'Only local fields are reverted; executed actions are never changed.';
    undoToolbar.append(undoButton, undoStatus);
    form.insertAdjacentElement('afterbegin', undoToolbar);
    let focusedField = null;
    let focusedState = null;

    function editableField(element) {
      return element && /^(INPUT|TEXTAREA|SELECT)$/.test(element.tagName) && element.type !== 'hidden';
    }
    function fieldState(element) {
      if (element.type === 'checkbox' || element.type === 'radio') return { checked: element.checked };
      if (element.multiple) return { selected: [...element.options].map(function (option) { return option.selected; }) };
      return { value: element.value };
    }
    function sameState(left, right) { return JSON.stringify(left) === JSON.stringify(right); }
    function restoreField(element, state) {
      if ('checked' in state) element.checked = state.checked;
      else if ('selected' in state) [...element.options].forEach(function (option, index) { option.selected = state.selected[index]; });
      else element.value = state.value;
      element.dispatchEvent(new Event('input', { bubbles: true }));
      element.dispatchEvent(new Event('change', { bubbles: true }));
      element.focus();
    }
    form.addEventListener('focusin', function (event) {
      if (!editableField(event.target)) return;
      focusedField = event.target;
      focusedState = fieldState(event.target);
    });
    form.addEventListener('focusout', function (event) {
      if (event.target !== focusedField || focusedState === null) return;
      const currentState = fieldState(focusedField);
      if (!sameState(currentState, focusedState)) {
        undoStack.push({ field: focusedField, state: focusedState });
        undoButton.disabled = false;
      }
      focusedField = null;
      focusedState = null;
    });
    undoButton.addEventListener('click', function () {
      const edit = undoStack.pop();
      if (!edit) return;
      restoreField(edit.field, edit.state);
      undoButton.disabled = undoStack.length === 0;
      undoStatus.textContent = form.dataset.undoStatus || 'Last local edit reverted. Saving remains an explicit decision.';
    });
    form.addEventListener('input', function () { dirty = true; });
    form.addEventListener('change', function () { dirty = true; });
    form.addEventListener('submit', function (event) {
      // Otros listeners pueden cancelar el submit (por ejemplo, la
      // validación manual del wizard). Esperar al final del ciclo evita
      // considerar guardado un formulario cuyo envío nunca ocurrió.
      window.setTimeout(function () {
        if (!event.defaultPrevented) dirty = false;
      }, 0);
    });
    window.addEventListener('beforeunload', function (event) {
      if (!dirty) return;
      event.preventDefault();
      event.returnValue = '';
    });
  });
})();

// Cabecera con el testigo CSRF, para los `fetch()` que arman su propio cuerpo
// y por lo tanto no arrastran el campo oculto del formulario. Un `fetch` que
// manda `new FormData(form)` no la necesita: el campo ya viaja adentro.
// Ver apate.web._csrf para por que toda mutacion lo exige.
window.apateCsrfHeaders = function () {
  var meta = document.querySelector('meta[name="csrf-token"]');
  return meta && meta.content ? { 'X-CSRF-Token': meta.content } : {};
};
