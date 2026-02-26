const fs = require('fs');
const data = JSON.parse(fs.readFileSync('/Users/nahumkorda/code/test_repos/Flowise/flowise_routes_dataset.json', 'utf-8'));

console.log('='.repeat(80));
console.log('FLOWISE ROUTE EXTRACTION TRANSPARENCY REPORT');
console.log('='.repeat(80));
console.log();

console.log('EXTRACTION STATISTICS');
console.log('-'.repeat(40));
console.log('Total routes extracted:', data.extraction_stats.total_routes);
console.log('Routes with handler code:', data.extraction_stats.routes_with_code);
console.log('Routes without handler code:', data.extraction_stats.routes_without_code);
console.log('Extraction rate:', data.extraction_stats.extraction_rate);
console.log();

console.log('BREAKDOWN BY HTTP METHOD');
console.log('-'.repeat(40));
const methodCounts = {};
data.units.forEach(u => {
    methodCounts[u.route.method] = (methodCounts[u.route.method] || 0) + 1;
});
Object.entries(methodCounts).sort().forEach(([method, count]) => {
    console.log('  ' + method + ':', count);
});
console.log();

console.log('HANDLER CODE SAMPLE VERIFICATION');
console.log('-'.repeat(40));
// Sample 5 routes to verify code extraction
const samples = [
    data.units.find(u => u.route.path === '/user' && u.route.method === 'GET'),  // Enterprise class controller
    data.units.find(u => u.route.path === '/oauth2-credential/callback'),  // Inline handler
    data.units.find(u => u.route.path === '/chatmessage' && u.route.method === 'GET'),  // Default import controller
    data.units.find(u => u.route.path === '/credentials' && u.route.method === 'POST'),
    data.units.find(u => u.route.path === '/ping')
];

samples.filter(Boolean).forEach((unit, i) => {
    console.log();
    console.log((i+1) + '. Route:', unit.route.method, unit.route.path);
    console.log('   Handler:', unit.route.handler);
    console.log('   Source file:', unit.code.primary_origin.file_path);
    console.log('   Line range:', unit.code.primary_origin.start_line, '-', unit.code.primary_origin.end_line);
    console.log('   Code length:', unit.code.primary_code.length, 'chars');
    console.log('   Code preview:');
    const preview = unit.code.primary_code.substring(0, 200).replace(/\n/g, '\\n');
    console.log('   ', preview + (unit.code.primary_code.length > 200 ? '...' : ''));
});
console.log();

console.log('ALL ROUTES BY BASE PATH');
console.log('-'.repeat(40));
const byBasePath = {};
data.units.forEach(u => {
    const basePath = '/' + u.route.path.split('/')[1];
    if (!byBasePath[basePath]) byBasePath[basePath] = [];
    byBasePath[basePath].push(u);
});
Object.entries(byBasePath).sort().forEach(([basePath, routes]) => {
    const withCode = routes.filter(r => r.metadata.has_handler_code).length;
    console.log('  ' + basePath.padEnd(30) + routes.length + ' routes, ' + withCode + ' with code');
});
console.log();

console.log('DATASET READY FOR ANALYSIS:', data.units.every(u => u.metadata.has_handler_code) ? 'YES' : 'NO');
