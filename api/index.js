const { app, initialize } = require('../server');

let ready = null;

module.exports = async (req, res) => {
    try {
        if (!ready) ready = initialize();
        await ready;
    } catch (err) {
        ready = null;
        console.error('Initialization failed:', err);
        return res.status(500).json({
            success: false,
            message: 'The attendance service could not start. Check the database configuration.'
        });
    }
    return app(req, res);
};
