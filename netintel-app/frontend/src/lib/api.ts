import { ImportFile, ImportFilePath, GetScanData, GetDashboardStats, ClearData, ExportJSON, ExportCSV } from '../../wailsjs/go/main/App';
import { scanData, dashboardStats } from './stores';

export async function importFile() {
  const result = await ImportFile();
  if (result) {
    scanData.set(result);
    await refreshStats();
  }
  return result;
}

export async function importFilePath(path: string) {
  const result = await ImportFilePath(path);
  if (result) {
    scanData.set(result);
    await refreshStats();
  }
  return result;
}

export async function loadData() {
  const data = await GetScanData();
  scanData.set(data);
  await refreshStats();
  return data;
}

export async function refreshStats() {
  const stats = await GetDashboardStats();
  dashboardStats.set(stats);
  return stats;
}

export async function clearData() {
  await ClearData();
  scanData.set({ hosts: [], sources: [] });
  dashboardStats.set(null);
}

export { ExportJSON, ExportCSV };
