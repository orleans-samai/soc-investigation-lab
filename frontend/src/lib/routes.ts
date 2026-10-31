// Detail pages take the record id as a query parameter so the UI can be exported as static files
// (the desktop app serves it from the bundled backend, with no Node.js server).
const detail = (section: string) => (id: string) => `/${section}/view?id=${encodeURIComponent(id)}`;

export const alertHref = detail("alerts");
export const incidentHref = detail("incidents");
export const reportHref = detail("reports");
