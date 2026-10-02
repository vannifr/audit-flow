const rows = [{ id: 1, name: 'alice', email: 'alice@example.org' }];

function query(sql) {
  return rows.filter(() => sql.length > 0);
}

module.exports = { query };
