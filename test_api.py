#!/usr/bin/env python3
"""
Test suite for Email Classifier API
"""

import unittest
import json
import os
import sys
from unittest.mock import patch, MagicMock

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app, classify_email, EMAIL_CATEGORIES

class EmailClassifierTestCase(unittest.TestCase):
    """Test cases for Email Classifier API"""
    
    def setUp(self):
        """Set up test client and environment"""
        app.config['TESTING'] = True
        self.client = app.test_client()
        
        # Set a dummy API key for testing
        os.environ['OPENAI_API_KEY'] = 'test_key'
    
    def tearDown(self):
        """Clean up after tests"""
        pass
    
    def test_index_page(self):
        """Test the main page loads correctly"""
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Email Classifier', response.data)
    
    def test_health_check(self):
        """Test health check endpoint"""
        response = self.client.get('/health')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data['status'], 'healthy')
        self.assertEqual(data['service'], 'email-classifier')
    
    def test_get_categories(self):
        """Test categories endpoint"""
        response = self.client.get('/api/categories')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn('categories', data)
        self.assertEqual(data['categories'], EMAIL_CATEGORIES)
    
    def test_classify_email_missing_data(self):
        """Test classification with missing data"""
        response = self.client.post('/api/classify', 
                                  data=json.dumps({}),
                                  content_type='application/json')
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.data)
        self.assertIn('error', data)
    
    def test_classify_email_missing_content(self):
        """Test classification with missing content"""
        response = self.client.post('/api/classify',
                                  data=json.dumps({'subject': 'Test'}),
                                  content_type='application/json')
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.data)
        self.assertIn('error', data)
    
    @patch('app.openai.ChatCompletion.create')
    def test_classify_email_success(self, mock_openai):
        """Test successful email classification"""
        # Mock OpenAI response
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = 'work'
        mock_openai.return_value = mock_response
        
        test_data = {
            'subject': 'Project Update',
            'content': 'Hi team, here is the project update for this week.'
        }
        
        response = self.client.post('/api/classify',
                                  data=json.dumps(test_data),
                                  content_type='application/json')
        
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn('category', data)
        self.assertEqual(data['category'], 'work')
        self.assertIn('categories', data)
    
    @patch('app.openai.ChatCompletion.create')
    def test_classify_email_invalid_category(self, mock_openai):
        """Test classification with invalid category response"""
        # Mock OpenAI response with invalid category
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = 'invalid_category'
        mock_openai.return_value = mock_response
        
        test_data = {
            'content': 'Test email content'
        }
        
        response = self.client.post('/api/classify',
                                  data=json.dumps(test_data),
                                  content_type='application/json')
        
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data['category'], 'other')  # Should default to 'other'
    
    @patch('app.openai.ChatCompletion.create')
    def test_classify_email_api_error(self, mock_openai):
        """Test classification when OpenAI API fails"""
        # Mock OpenAI API error
        mock_openai.side_effect = Exception("API Error")
        
        test_data = {
            'content': 'Test email content'
        }
        
        response = self.client.post('/api/classify',
                                  data=json.dumps(test_data),
                                  content_type='application/json')
        
        self.assertEqual(response.status_code, 500)
        data = json.loads(response.data)
        self.assertIn('error', data)
    
    def test_classify_email_function(self):
        """Test the classify_email function directly"""
        with patch('app.openai.ChatCompletion.create') as mock_openai:
            # Mock successful response
            mock_response = MagicMock()
            mock_response.choices = [MagicMock()]
            mock_response.choices[0].message.content = 'personal'
            mock_openai.return_value = mock_response
            
            result = classify_email('Hello, how are you?', 'Greeting')
            self.assertEqual(result, 'personal')
    
    def test_classify_email_function_error(self):
        """Test the classify_email function with API error"""
        with patch('app.openai.ChatCompletion.create') as mock_openai:
            # Mock API error
            mock_openai.side_effect = Exception("API Error")
            
            result = classify_email('Test content')
            self.assertEqual(result, 'error')

class EmailClassifierIntegrationTestCase(unittest.TestCase):
    """Integration tests for Email Classifier"""
    
    def setUp(self):
        """Set up test client"""
        app.config['TESTING'] = True
        self.client = app.test_client()
        os.environ['OPENAI_API_KEY'] = 'test_key'
    
    def test_full_classification_flow(self):
        """Test the complete classification flow"""
        # Test data for different email types
        test_cases = [
            {
                'name': 'Spam Email',
                'data': {
                    'subject': 'URGENT: You won $1,000,000!',
                    'content': 'CONGRATULATIONS! You have been selected to receive $1,000,000!'
                }
            },
            {
                'name': 'Work Email',
                'data': {
                    'subject': 'Project Update',
                    'content': 'Hi team, here is the weekly project update. Please review the attached documents.'
                }
            },
            {
                'name': 'Personal Email',
                'data': {
                    'subject': 'Dinner plans',
                    'content': 'Hey! How about dinner this weekend? I found a great new restaurant.'
                }
            }
        ]
        
        for test_case in test_cases:
            with self.subTest(test_case['name']):
                with patch('app.openai.ChatCompletion.create') as mock_openai:
                    # Mock response based on test case
                    mock_response = MagicMock()
                    mock_response.choices = [MagicMock()]
                    
                    # Determine expected category based on content
                    content = test_case['data']['content'].lower()
                    if 'congratulations' in content or 'urgent' in content:
                        expected_category = 'spam'
                    elif 'team' in content or 'project' in content:
                        expected_category = 'work'
                    else:
                        expected_category = 'personal'
                    
                    mock_response.choices[0].message.content = expected_category
                    mock_openai.return_value = mock_response
                    
                    response = self.client.post('/api/classify',
                                              data=json.dumps(test_case['data']),
                                              content_type='application/json')
                    
                    self.assertEqual(response.status_code, 200)
                    data = json.loads(response.data)
                    self.assertEqual(data['category'], expected_category)

def run_tests():
    """Run all tests"""
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add test cases
    test_suite.addTest(unittest.TestLoader().loadTestsFromTestCase(EmailClassifierTestCase))
    test_suite.addTest(unittest.TestLoader().loadTestsFromTestCase(EmailClassifierIntegrationTestCase))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    return result.wasSuccessful()

if __name__ == '__main__':
    print("🧪 Running Email Classifier Tests...")
    success = run_tests()
    
    if success:
        print("✅ All tests passed!")
        sys.exit(0)
    else:
        print("❌ Some tests failed!")
        sys.exit(1)
