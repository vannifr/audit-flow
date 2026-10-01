module.exports = {
  default: {
    paths: ['specs/*/tests/features/**/*.feature'],
    require: ['tests/step_definitions/**/*.ts'],
    format: ['progress', 'html:coverage/cucumber-report.html'],
    publishQuiet: true,
  },
};