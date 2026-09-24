// Presentation-only filtering; commands still submit through native signed forms.
document.addEventListener("input", (event) => {
  if (event.target.id !== "link-search") return;
  const query = event.target.value.toLocaleLowerCase();
  for (const row of document.querySelectorAll(".link-row")) {
    row.hidden = !row.dataset.title.toLocaleLowerCase().includes(query);
  }
});
