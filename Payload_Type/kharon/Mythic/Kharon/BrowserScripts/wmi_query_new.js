function(task, responses){
    function formatCSV(csvData) {
        try {
            // Clean up the data first
            csvData = csvData.trim();
            
            // More robust delimiter detection
            let delimiter = /[,;\t|]/.exec(csvData)?.[0] || ',';
            
            const lines = csvData.split('\n').filter(line => line.trim() !== '');
            
            if (lines.length < 1) {
                return {'plaintext': 'No data found in CSV'};
            }

            // Process headers - more robust splitting
            const headers = lines[0].split(delimiter)
                .map(h => h.trim())
                .filter(h => h !== '');
            
            if (headers.length === 0) {
                return {'plaintext': 'No valid headers found in CSV'};
            }

            // Process rows
            const rows = [];
            for (let i = 1; i < lines.length; i++) {
                // More robust row splitting that handles quoted values
                const cells = lines[i].split(delimiter)
                    .map(c => c.trim().replace(/^['"]|['"]$/g, ''))
                    .filter(c => c !== '');
                
                if (cells.length === 0) continue;
                
                // Handle cases where row has fewer cells than headers
                const row = {};
                headers.forEach((header, index) => {
                    row[header] = index < cells.length ? cells[index] : '';
                });
                rows.push(row);
            }

            // If no rows found, show at least the headers
            if (rows.length === 0) {
                return {
                    'plaintext': 'Headers found but no data rows:\n' + headers.join(', ')
                };
            }

            // Create table structure
            const tableHeaders = headers.map(header => ({
                'plaintext': header,
                'type': 'string',
                'fillWidth': true
            }));

            const tableRows = rows.map((row, rowIndex) => {
                const rowData = {};
                headers.forEach(header => {
                    rowData[header] = {
                        'plaintext': row[header] || ' ',
                        'copyIcon': true,
                        'hoverText': `Copy ${header} value`,
                        'style': {'color': '#333333'}
                    };
                });
                
                return {
                    'rowStyle': rowIndex % 2 === 0 
                        ? {'backgroundColor': '#f5f5f5'}
                        : {'backgroundColor': '#e8f4f8'},
                    ...rowData
                };
            });

            return {
                'table': [{
                    'headers': tableHeaders,
                    'rows': tableRows,
                    'title': 'CSV Formatted Data',
                    'headerStyle': {
                        'backgroundColor': '#2c3e50',
                        'color': 'white',
                        'fontWeight': 'bold',
                        'position': 'sticky',
                        'top': 0
                    },
                    'tableStyle': {
                        'border': '1px solid #ddd'
                    }
                }]
            };
            
        } catch (error) {
            return {'plaintext': `Error formatting CSV: ${error}\n\nOriginal data:\n${csvData}`};
        }
    }

    // Handle different task states
    if (task.status.includes("error")) {
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {'plaintext': combined};
    } else if (task.completed) {
        if (responses.length > 0) {
            try {
                // Combine all responses properly
                const combinedResponse = responses.join('\n');
                return formatCSV(combinedResponse);
            } catch (error) {
                return {'plaintext': `Error processing CSV data: ${error}\n\n${responses.join('\n')}`};
            }
        } else {
            return {'plaintext': "No data to display..."};
        }
    } else if (task.status === "processed") {
        return {'plaintext': "Processing CSV data..."};
    } else {
        return {'plaintext': "Waiting for agent response..."};
    }
}