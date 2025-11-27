module.exports = (request, response, next) => {
    if (!request.session || !request.session.isLoggedIn) {
        return response.redirect('/login');
    }
    next();
};