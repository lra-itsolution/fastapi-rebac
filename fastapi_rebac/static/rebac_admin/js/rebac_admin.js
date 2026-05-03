(function () {
  "use strict";

  document.documentElement.classList.add("js-enabled");

  function nonEmptyOptionValues(select) {
    var values = [];
    if (!(select instanceof HTMLSelectElement)) {
      return values;
    }
    for (var i = 0; i < select.options.length; i += 1) {
      var value = select.options[i].value.trim();
      if (value) {
        values.push(value);
      }
    }
    return values;
  }

  function findOptionByValue(select, value) {
    if (!(select instanceof HTMLSelectElement) || !value) {
      return null;
    }
    for (var i = 0; i < select.options.length; i += 1) {
      if (select.options[i].value === value) {
        return select.options[i];
      }
    }
    return null;
  }

  function getForeignKeyParts(widget) {
    return {
      select: widget.querySelector("[data-fk-select]"),
      manualInput: widget.querySelector("[data-fk-manual]")
    };
  }

  function syncForeignKeyFromSelect(widget) {
    var parts = getForeignKeyParts(widget);
    var select = parts.select;
    var manualInput = parts.manualInput;

    if (select instanceof HTMLSelectElement && manualInput instanceof HTMLInputElement) {
      manualInput.value = select.value.trim();
    }
  }

  function syncForeignKeyFromManual(widget) {
    var parts = getForeignKeyParts(widget);
    var select = parts.select;
    var manualInput = parts.manualInput;

    if (!(select instanceof HTMLSelectElement) || !(manualInput instanceof HTMLInputElement)) {
      return;
    }

    var manualValue = manualInput.value.trim();
    if (!manualValue) {
      select.value = "";
      return;
    }

    var matchingOption = findOptionByValue(select, manualValue);
    if (matchingOption) {
      select.value = manualValue;
      return;
    }

    // Keep the manually typed ID visible/editable, but mark the select as unresolved.
    // The submit validator will block saving until the ID matches one of the loaded choices.
    select.value = "";
  }

  function validateForeignKeyWidget(widget) {
    var parts = getForeignKeyParts(widget);
    var select = parts.select;
    var manualInput = parts.manualInput;
    var required = widget.classList.contains("is-required") || widget.getAttribute("data-required") === "1";

    if (!(manualInput instanceof HTMLInputElement)) {
      return true;
    }

    var manualValue = manualInput.value.trim();
    var selectedValue = select instanceof HTMLSelectElement ? select.value.trim() : "";
    var hasChoices = nonEmptyOptionValues(select).length > 0;

    if (!required && !manualValue && !selectedValue) {
      return true;
    }

    if (select instanceof HTMLSelectElement) {
      if (manualValue) {
        var matchingOption = findOptionByValue(select, manualValue);
        if (matchingOption) {
          select.value = manualValue;
          selectedValue = manualValue;
        }
      }
    }

    if (required && (!manualValue || !selectedValue)) {
      return false;
    }

    if (manualValue && hasChoices && !selectedValue) {
      return false;
    }

    if (manualValue && selectedValue && manualValue !== selectedValue) {
      return false;
    }

    return true;
  }

  document.addEventListener("click", function (event) {
    var target = event.target;

    if (!(target instanceof HTMLElement)) {
      return;
    }

    var dangerButton = target.closest("[data-confirm]");
    if (!dangerButton) {
      return;
    }

    var message = dangerButton.getAttribute("data-confirm") || "Are you sure?";
    if (!window.confirm(message)) {
      event.preventDefault();
    }
  });

  document.addEventListener("submit", function (event) {
    var form = event.target;

    if (!(form instanceof HTMLFormElement)) {
      return;
    }

    var widgets = form.querySelectorAll("[data-fk-widget]");
    for (var i = 0; i < widgets.length; i += 1) {
      var widget = widgets[i];
      if (!validateForeignKeyWidget(widget)) {
        event.preventDefault();
        var parts = getForeignKeyParts(widget);
        if (parts.manualInput instanceof HTMLInputElement) {
          parts.manualInput.focus();
        } else if (parts.select instanceof HTMLSelectElement) {
          parts.select.focus();
        }
        window.alert("Choose a related object from the list and keep its ID filled in.");
        return;
      }
    }
  });

  document.addEventListener("change", function (event) {
    var target = event.target;

    if (!(target instanceof HTMLSelectElement) || !target.matches("[data-fk-select]")) {
      return;
    }

    var widget = target.closest("[data-fk-widget]");
    if (!widget) {
      return;
    }

    syncForeignKeyFromSelect(widget);
  });

  document.addEventListener("input", function (event) {
    var target = event.target;

    if (!(target instanceof HTMLInputElement) || !target.matches("[data-fk-manual]")) {
      return;
    }

    var widget = target.closest("[data-fk-widget]");
    if (!widget) {
      return;
    }

    syncForeignKeyFromManual(widget);
  });
})();
