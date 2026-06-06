// Drag-and-drop upload UX + submit feedback.
(function () {
  const dropzone = document.getElementById("dropzone");
  const input = document.getElementById("fileInput");
  const label = document.getElementById("fileLabel");
  const submitBtn = document.getElementById("submitBtn");
  const form = document.getElementById("uploadForm");
  const spinner = document.getElementById("spinner");
  const btnText = document.getElementById("btnText");

  if (!dropzone || !input) return;

  function updateLabel() {
    if (input.files.length) {
      const f = input.files[0];
      const kb = (f.size / 1024).toFixed(1);
      label.textContent = `${f.name} (${kb} KB)`;
      submitBtn.disabled = false;
    } else {
      label.textContent = "No file selected";
      submitBtn.disabled = true;
    }
  }

  input.addEventListener("change", updateLabel);

  ["dragenter", "dragover"].forEach((evt) =>
    dropzone.addEventListener(evt, (e) => {
      e.preventDefault();
      dropzone.classList.add("dragover");
    })
  );
  ["dragleave", "drop"].forEach((evt) =>
    dropzone.addEventListener(evt, (e) => {
      e.preventDefault();
      dropzone.classList.remove("dragover");
    })
  );
  dropzone.addEventListener("drop", (e) => {
    if (e.dataTransfer.files.length) {
      input.files = e.dataTransfer.files;
      updateLabel();
    }
  });

  form.addEventListener("submit", () => {
    spinner.classList.remove("d-none");
    btnText.textContent = " Scanning…";
    submitBtn.disabled = true;
  });
})();
