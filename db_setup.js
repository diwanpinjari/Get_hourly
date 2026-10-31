const { db, initialize } = require('./server');
initialize().then(() => {
    db.close();
    console.log('Database initialized.');
}).catch(err => { console.error(err); db.close(); process.exitCode = 1; });
