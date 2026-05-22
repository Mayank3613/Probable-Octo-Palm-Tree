// OctoPlamTree Download Scanner Module (ES6 module used by background.js)

const DANGEROUS_EXTENSIONS = [
  "exe", "msi", "bat", "cmd", "scr", "vbs", "js", "jse", 
  "wsf", "wsh", "pif", "lnk", "reg", "hta", "cpl", "jar"
];

export function scanDownload(downloadItem) {
  const filename = downloadItem.filename || "";
  const url = downloadItem.url || "";
  
  const results = {
    isSuspicious: false,
    score: 0,
    reason: ""
  };

  if (!filename) return results;

  // Extract extension
  const cleanFilename = filename.split('\\').pop().split('/').pop();
  const fileParts = cleanFilename.split('.');
  
  if (fileParts.length < 2) return results;
  
  const primaryExtension = fileParts.pop().toLowerCase();
  
  // Heuristic 1: Check for double extension (e.g. document.pdf.exe, invoice.docx.vbs)
  if (fileParts.length >= 2) {
    const secondaryExtension = fileParts.pop().toLowerCase();
    const commonSafeExts = ["pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "png", "jpg", "jpeg", "txt", "zip"];
    
    if (commonSafeExts.includes(secondaryExtension) && DANGEROUS_EXTENSIONS.includes(primaryExtension)) {
      results.isSuspicious = true;
      results.score = 90;
      results.reason = `Double-extension attack vector detected: '.${secondaryExtension}.${primaryExtension}'`;
      return results;
    }
  }

  // Heuristic 2: Check for dangerous executable extension
  if (DANGEROUS_EXTENSIONS.includes(primaryExtension)) {
    results.isSuspicious = true;
    results.score = 50;
    results.reason = `Potentially dangerous executable file extension: '.${primaryExtension}'`;
    return results;
  }

  // Heuristic 3: Check if downloaded from suspicious domain (passed from background URL scanner)
  return results;
}
