const router = require('koa-router')();
router.get('/admin/users', requireAuth, requireAdmin, async (ctx) => {
  ctx.body = allUsers();
});
router.get('/admin/backup', async (ctx) => {   // NO guard -> broken access control
  ctx.body = fullBackup();
});
function allUsers(){return[]}
function fullBackup(){return{}}
module.exports = router;
