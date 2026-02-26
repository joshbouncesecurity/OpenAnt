/**
 * Dataset Enhancer
 *
 * Reads an existing dataset and enhances each unit with complete code context
 * using the ContextAssembler.
 */

const fs = require('fs');
const path = require('path');
const { ContextAssembler } = require('./context_assembler');

// Repository paths for each dataset
const REPOS = {
    'dvna': '/Users/nahumkorda/code/dvna',
    'nodegoat': '/Users/nahumkorda/code/NodeGoat',
    'juice_shop': '/Users/nahumkorda/code/juice-shop'
};

/**
 * Enhance a single dataset with complete code context
 */
async function enhanceDataset(datasetPath, outputPath) {
    // Load the original dataset
    const dataset = JSON.parse(fs.readFileSync(datasetPath, 'utf-8'));
    const datasetName = dataset.name || path.basename(path.dirname(datasetPath));

    console.log(`Enhancing dataset: ${datasetName}`);
    console.log(`Input: ${datasetPath}`);
    console.log(`Output: ${outputPath}`);
    console.log('');

    // Get the repository path
    const repoPath = dataset.repository_path || REPOS[datasetName];
    if (!repoPath || !fs.existsSync(repoPath)) {
        console.error(`Repository not found for ${datasetName}: ${repoPath}`);
        process.exit(1);
    }

    console.log(`Repository: ${repoPath}`);

    // Initialize the context assembler
    const assembler = new ContextAssembler(repoPath, {
        maxDepth: 5,
        maxFiles: 20
    });

    try {
        const fileCount = assembler.initializeProgram();
        console.log(`Found ${fileCount} source files`);
    } catch (error) {
        console.error(`Error initializing program: ${error.message}`);
        process.exit(1);
    }

    console.log('');
    console.log('Processing units...');
    console.log('-'.repeat(60));

    // Process each unit
    const enhancedUnits = [];
    const stats = {
        total: dataset.units.length,
        enhanced: 0,
        failed: 0,
        originalChars: 0,
        enhancedChars: 0
    };

    for (let i = 0; i < dataset.units.length; i++) {
        const unit = dataset.units[i];
        const routeFile = unit.metadata?.route_file || unit.code?.primary_origin?.file_path;
        const handler = unit.route?.handler || 'main';
        const routePath = unit.route?.path || null;  // Extract route path for template filtering

        console.log(`[${i + 1}/${stats.total}] ${unit.id}`);

        // Track original size
        const originalCode = typeof unit.code === 'string'
            ? unit.code
            : (unit.code?.primary_code || '');
        stats.originalChars += originalCode.length;

        if (!routeFile) {
            console.log(`  ⚠ No route file found, keeping original code`);
            enhancedUnits.push(unit);
            stats.failed++;
            continue;
        }

        try {
            // Assemble context for this route, passing the route path for template filtering
            const result = assembler.assembleContext(routeFile, handler, routePath);

            if (!result.success) {
                console.log(`  ⚠ Failed: ${result.error}`);
                enhancedUnits.push(unit);
                stats.failed++;
                continue;
            }

            // Create enhanced unit
            const enhancedUnit = {
                ...unit,
                code: {
                    ...unit.code,
                    primary_code: result.code,
                    primary_origin: {
                        ...(unit.code?.primary_origin || {}),
                        enhanced: true,
                        files_included: result.files.map(f => f.relativePath),
                        original_length: originalCode.length,
                        enhanced_length: result.code.length
                    },
                    // Store enhancement metadata
                    enhancement_stats: {
                        files_visited: result.stats.filesVisited,
                        symbols_resolved: result.stats.symbolsResolved,
                        external_modules: result.stats.externalModules,
                        unresolved_imports: result.stats.unresolvedImports
                    }
                }
            };

            enhancedUnits.push(enhancedUnit);
            stats.enhanced++;
            stats.enhancedChars += result.code.length;

            console.log(`  ✓ Enhanced: ${originalCode.length} → ${result.code.length} chars (${result.stats.filesVisited} files)`);

        } catch (error) {
            console.log(`  ✗ Error: ${error.message}`);
            enhancedUnits.push(unit);
            stats.failed++;
        }
    }

    console.log('');
    console.log('='.repeat(60));
    console.log('ENHANCEMENT SUMMARY');
    console.log('='.repeat(60));
    console.log(`Total units: ${stats.total}`);
    console.log(`Successfully enhanced: ${stats.enhanced}`);
    console.log(`Failed/skipped: ${stats.failed}`);
    console.log(`Original code size: ${stats.originalChars.toLocaleString()} chars`);
    console.log(`Enhanced code size: ${stats.enhancedChars.toLocaleString()} chars`);
    console.log(`Size increase: ${((stats.enhancedChars / stats.originalChars - 1) * 100).toFixed(1)}%`);

    // Create enhanced dataset
    const enhancedDataset = {
        ...dataset,
        name: dataset.name + '_enhanced',
        units: enhancedUnits,
        enhancement_metadata: {
            original_dataset: datasetPath,
            enhanced_at: new Date().toISOString(),
            stats: stats
        }
    };

    // Write output
    fs.writeFileSync(outputPath, JSON.stringify(enhancedDataset, null, 2));
    console.log('');
    console.log(`Enhanced dataset saved to: ${outputPath}`);

    return stats;
}

/**
 * CLI interface
 */
async function main() {
    const args = process.argv.slice(2);

    if (args.length < 1) {
        console.log('Usage: node dataset_enhancer.js <dataset_path> [output_path]');
        console.log('');
        console.log('Examples:');
        console.log('  node dataset_enhancer.js ../datasets/dvna/dataset.json');
        console.log('  node dataset_enhancer.js ../datasets/dvna/dataset.json ../datasets/dvna/dataset_enhanced.json');
        process.exit(1);
    }

    const datasetPath = path.resolve(args[0]);
    const outputPath = args[1]
        ? path.resolve(args[1])
        : datasetPath.replace('.json', '_enhanced.json');

    if (!fs.existsSync(datasetPath)) {
        console.error(`Dataset not found: ${datasetPath}`);
        process.exit(1);
    }

    await enhanceDataset(datasetPath, outputPath);
}

// Run CLI
main().catch(error => {
    console.error(`Fatal error: ${error.message}`);
    process.exit(1);
});
