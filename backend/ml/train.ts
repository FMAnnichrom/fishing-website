import path from 'node:path';
import { trainUrlClassifier } from './trainer';

const datasetPath = path.resolve(process.cwd(), 'ml-service/datasets/urls_dataset.csv');
const modelOutputPath = path.resolve(process.cwd(), 'ml-service/models/url_classifier_model.json');

const artifact = trainUrlClassifier(datasetPath, modelOutputPath);

console.log('Trained URL Phishing Classifier successfully.');
console.log('Model saved to:', modelOutputPath);
console.log('Dataset stats:', artifact.evaluation.datasetStats);
console.log('Validation metrics:', artifact.evaluation.validationMetrics);
console.log('Test metrics:', artifact.evaluation.testMetrics);
