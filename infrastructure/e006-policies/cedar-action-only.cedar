// Action-type authorization. The action is constrained; the resource is not.
// Nothing here consults which organization the document belongs to.
permit(
  principal == User::"G",
  action == Action::"read",
  resource
);
