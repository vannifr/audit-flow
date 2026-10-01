module.exports = {
  default: {
    paths: ['specs/*/tests/features/**/*.feature'],
    require: ['tests/step_definitions/**/*.ts'],
    requireModule: ['ts-node/register'],
    format: ['progress', 'html:coverage/cucumber-report.html'],
    publishQuiet: true,
  },
};