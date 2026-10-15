from burp import IBurpExtender, ITab, IHttpListener, IMessageEditorController
from javax.swing import (JPanel, JTextField, JLabel, JButton, JScrollPane, 
                         JTextArea, BoxLayout, JSpinner, SpinnerNumberModel,
                         BorderFactory, JCheckBox, SwingConstants)
from javax.swing.border import EmptyBorder
from java.awt import BorderLayout, FlowLayout, Dimension, GridBagLayout, GridBagConstraints, Insets
from java.awt.datatransfer import StringSelection
from java.awt import Toolkit
import java.lang as lang
from threading import Thread
import time
import random
import math

class BurpExtender(IBurpExtender, ITab, IHttpListener, IMessageEditorController):
    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("IDOR Smart Guesser")
        
        # Create UI
        self._panel = JPanel(BorderLayout())
        self._panel.setBorder(EmptyBorder(10, 10, 10, 10))
        
        # Top panel for inputs
        topPanel = JPanel()
        topPanel.setLayout(GridBagLayout())
        topPanel.setBorder(BorderFactory.createTitledBorder("IDOR Configuration"))
        
        gbc = GridBagConstraints()
        gbc.fill = GridBagConstraints.HORIZONTAL
        gbc.insets = Insets(5, 5, 5, 5)
        
        # Range inputs
        gbc.gridx = 0
        gbc.gridy = 0
        topPanel.add(JLabel("Start Range:"), gbc)
        
        gbc.gridx = 1
        self._startField = JSpinner(SpinnerNumberModel(1, 1, 999999999, 1))
        self._startField.setPreferredSize(Dimension(150, 25))
        topPanel.add(self._startField, gbc)
        
        gbc.gridx = 2
        topPanel.add(JLabel("End Range:"), gbc)
        
        gbc.gridx = 3
        self._endField = JSpinner(SpinnerNumberModel(900000, 1, 999999999, 1))
        self._endField.setPreferredSize(Dimension(150, 25))
        topPanel.add(self._endField, gbc)
        
        # Number of requests
        gbc.gridx = 0
        gbc.gridy = 1
        topPanel.add(JLabel("Number of Requests:"), gbc)
        
        gbc.gridx = 1
        self._numRequestsField = JSpinner(SpinnerNumberModel(500, 10, 10000, 10))
        self._numRequestsField.setPreferredSize(Dimension(150, 25))
        topPanel.add(self._numRequestsField, gbc)
        
        # Strategy checkboxes
        gbc.gridx = 2
        gbc.gridy = 1
        topPanel.add(JLabel("Strategy:"), gbc)
        
        gbc.gridx = 3
        strategyPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        self._smartSampling = JCheckBox("Smart Sampling", True)
        self._edgeCases = JCheckBox("Edge Cases", True)
        strategyPanel.add(self._smartSampling)
        strategyPanel.add(self._edgeCases)
        topPanel.add(strategyPanel, gbc)
        
        # Generate button
        gbc.gridx = 0
        gbc.gridy = 2
        gbc.gridwidth = 4
        gbc.fill = GridBagConstraints.NONE
        self._generateBtn = JButton("Generate IDOR Guesses")
        self._generateBtn.addActionListener(self.generateGuesses)
        topPanel.add(self._generateBtn, gbc)
        
        self._panel.add(topPanel, BorderLayout.NORTH)
        
        # Output area
        outputPanel = JPanel(BorderLayout())
        outputPanel.setBorder(BorderFactory.createTitledBorder("Generated Numbers"))
        
        self._outputArea = JTextArea(20, 60)
        self._outputArea.setEditable(False)
        scrollPane = JScrollPane(self._outputArea)
        outputPanel.add(scrollPane, BorderLayout.CENTER)
        
        # Bottom panel with stats and copy button
        bottomPanel = JPanel(BorderLayout())
        self._statsLabel = JLabel("Ready to generate IDOR guesses", SwingConstants.CENTER)
        bottomPanel.add(self._statsLabel, BorderLayout.CENTER)
        
        self._copyBtn = JButton("Copy Results")
        self._copyBtn.addActionListener(self.copyResults)
        self._copyBtn.setEnabled(False)
        bottomPanel.add(self._copyBtn, BorderLayout.EAST)
        
        outputPanel.add(bottomPanel, BorderLayout.SOUTH)
        
        self._panel.add(outputPanel, BorderLayout.CENTER)
        
        # Add tab to Burp
        callbacks.addSuiteTab(self)
        
        # Register as HTTP listener
        callbacks.registerHttpListener(self)
        
        print("IDOR Smart Guesser extension loaded successfully!")
    
    def getTabCaption(self):
        return "IDOR Guesser"
    
    def getUiComponent(self):
        return self._panel
    
    def copyResults(self, event):
        """Copy the generated numbers to clipboard"""
        text = self._outputArea.getText()
        if text:
            selection = StringSelection(text)
            clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
            clipboard.setContents(selection, None)
            
            # Temporarily update button text to show success
            self._copyBtn.setText("Copied!")
            
            # Reset button text after 2 seconds
            def resetButtonText():
                time.sleep(2)
                self._copyBtn.setText("Copy Results")
            
            Thread(target=resetButtonText).start()
    
    def generateGuesses(self, event):
        """Generate smart IDOR guesses based on the configuration"""
        start = int(self._startField.getValue())
        end = int(self._endField.getValue())
        num_requests = int(self._numRequestsField.getValue())
        
        if start >= end:
            self._outputArea.setText("Error: Start range must be less than end range")
            return
        
        if num_requests > (end - start + 1):
            num_requests = end - start + 1
            self._outputArea.setText("Note: Reduced requests to maximum possible: %d\n\n" % num_requests)
        
        # Generate guesses based on selected strategies
        guesses = self._generateSmartGuesses(start, end, num_requests)
        
        # Display results - one number per line
        sorted_guesses = sorted(guesses)
        output = "\n".join(map(str, sorted_guesses))
        self._outputArea.setText(output)
        
        # Enable copy button
        self._copyBtn.setEnabled(True)
        
        # Update stats
        coverage = (float(len(guesses)) / (end - start + 1)) * 100
        self._statsLabel.setText("Generated %d unique guesses | Range coverage: %.2f%%" % (len(guesses), coverage))
    
    def _generateSmartGuesses(self, start, end, num_requests):
        """Generate intelligent IDOR guesses using multiple strategies"""
        guesses = set()
        
        # Strategy 1: Edge cases and boundaries
        if self._edgeCases.isSelected():
            edge_cases = self._getEdgeCases(start, end)
            guesses.update(edge_cases)
        
        # Strategy 2: Common patterns
        patterns = self._getCommonPatterns(start, end)
        guesses.update(patterns)
        
        # Strategy 3: Digit-based sampling
        if self._smartSampling.isSelected():
            # Determine digit ranges in the overall range
            digit_samples = self._getDigitBasedSamples(start, end, num_requests // 3)
            guesses.update(digit_samples)
        
        # Strategy 4: Statistical distribution
        remaining = num_requests - len(guesses)
        if remaining > 0:
            # Use logarithmic distribution to favor lower numbers (often more common in IDORs)
            log_samples = self._getLogDistributionSamples(start, end, remaining)
            guesses.update(log_samples)
        
        # Strategy 5: Fill remaining with strategic spacing
        remaining = num_requests - len(guesses)
        if remaining > 0:
            spaced_samples = self._getSpacedSamples(start, end, remaining, guesses)
            guesses.update(spaced_samples)
        
        # Ensure we don't exceed requested number
        final_guesses = list(guesses)
        if len(final_guesses) > num_requests:
            # Prioritize edge cases and patterns, random sample the rest
            prioritized = []
            
            # Keep all edge cases and patterns (usually most valuable)
            if self._edgeCases.isSelected():
                prioritized.extend([g for g in edge_cases if g in final_guesses])
            prioritized.extend([g for g in patterns if g in final_guesses and g not in prioritized])
            
            # Random sample from the rest
            remaining_guesses = [g for g in final_guesses if g not in prioritized]
            random.shuffle(remaining_guesses)
            
            final_guesses = prioritized + remaining_guesses[:num_requests - len(prioritized)]
        
        return final_guesses
    
    def _getEdgeCases(self, start, end):
        """Get edge cases and boundary values"""
        cases = set()
        
        # Start and end boundaries
        cases.add(start)
        cases.add(end)
        cases.add(start + 1)
        cases.add(end - 1)
        
        # Power of 10 boundaries
        for i in range(1, 10):
            power = 10 ** i
            if start <= power <= end:
                cases.add(power)
                cases.add(power - 1)
                cases.add(power + 1)
        
        # Round numbers
        for i in [100, 1000, 10000, 100000, 500000]:
            if start <= i <= end:
                cases.add(i)
        
        return cases
    
    def _getCommonPatterns(self, start, end):
        """Get common IDOR patterns"""
        patterns = set()
        
        # Sequential patterns (1234, 2345, etc.)
        for start_digit in range(1, 7):
            num = int(''.join(str(i) for i in range(start_digit, start_digit + 4)))
            if start <= num <= end:
                patterns.add(num)
        
        # Repeated digits (1111, 2222, etc.)
        for digit in range(1, 10):
            for length in range(2, 7):
                num = int(str(digit) * length)
                if start <= num <= end:
                    patterns.add(num)
        
        # Common test values
        test_values = [123, 1234, 12345, 123456, 111, 222, 333, 444, 555, 666, 777, 888, 999,
                      100, 200, 300, 400, 500, 1000, 2000, 3000, 4000, 5000, 10000]
        patterns.update([v for v in test_values if start <= v <= end])
        
        return patterns
    
    def _getDigitBasedSamples(self, start, end, count):
        """Sample based on digit length distribution"""
        samples = set()
        
        # Determine digit lengths in range
        start_digits = len(str(start))
        end_digits = len(str(end))
        
        # Allocate samples per digit length
        samples_per_digit = count // (end_digits - start_digits + 1)
        
        for digit_len in range(start_digits, end_digits + 1):
            range_start = max(start, 10 ** (digit_len - 1))
            range_end = min(end, (10 ** digit_len) - 1)
            
            if range_start <= range_end:
                # Sample from this digit length range
                for _ in range(samples_per_digit):
                    if range_start < range_end:
                        samples.add(random.randint(range_start, range_end))
        
        return samples
    
    def _getLogDistributionSamples(self, start, end, count):
        """Use logarithmic distribution (favors lower numbers)"""
        samples = set()
        range_size = end - start + 1
        
        for _ in range(count * 2):  # Generate extra to account for duplicates
            # Generate using log distribution
            u = random.random()
            # Transform uniform to log distribution
            x = int(start + (range_size - 1) * (math.exp(u * math.log(2)) - 1))
            if start <= x <= end:
                samples.add(x)
            
            if len(samples) >= count:
                break
        
        return samples
    
    def _getSpacedSamples(self, start, end, count, existing):
        """Generate evenly spaced samples avoiding existing guesses"""
        samples = set()
        
        # Calculate ideal spacing
        total_range = end - start + 1
        ideal_spacing = total_range // (count + 1)
        
        # Generate spaced samples
        current = start + ideal_spacing
        attempts = 0
        
        while len(samples) < count and attempts < count * 10:
            if current not in existing and start <= current <= end:
                samples.add(current)
                current += ideal_spacing
            else:
                # Add some randomness if we hit existing values
                offset = random.randint(-ideal_spacing//2, ideal_spacing//2)
                current += offset
            
            if current > end:
                current = start + random.randint(1, ideal_spacing)
            
            attempts += 1
        
        # Fill remaining with random samples
        while len(samples) < count:
            candidate = random.randint(start, end)
            if candidate not in existing:
                samples.add(candidate)
        
        return samples
    
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # This can be extended to automatically test generated IDs
        pass
    
    def getHttpService(self):
        return None
    
    def getRequest(self):
        return None
    
    def getResponse(self):
        return None