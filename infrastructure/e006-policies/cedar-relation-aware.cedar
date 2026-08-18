// Relation-scoped authorization. The document's owning organization must match
// the organization the grant was scoped to.
permit(
  principal == User::"G",
  action == Action::"read",
  resource
) when {
  resource.owner == Organization::"org-a"
};
