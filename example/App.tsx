/**
 * Crypto Atomics Key App
 * @format
 */

import {
  ActivityIndicator,
  Platform,
  StatusBar,
  StyleSheet,
  Text,
  TouchableOpacity,
  useColorScheme,
  View,
  ScrollView,
  TextInput,
} from 'react-native';
import { SafeAreaProvider, useSafeAreaInsets } from 'react-native-safe-area-context';
import { useCallback, useEffect, useRef, useState } from 'react';
import { CryptoAtomicsKey } from 'crypto-atomics-key';
import RNFS from 'react-native-fs';

type AppState = 'loading' | 'no-key' | 'generating' | 'ready';

function AppContent() {
  const isDarkMode = useColorScheme() === 'dark';
  const insets = useSafeAreaInsets();
  const [state, setState] = useState<AppState>('loading');
  const [progress, setProgress] = useState(0);
  const [privateKey, setPrivateKey] = useState('');
  const [message, setMessage] = useState('');
  const [signature, setSignature] = useState('');
  const [error, setError] = useState('');
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const colors = {
    bg: isDarkMode ? '#0D0D0D' : '#F5F5F7',
    card: isDarkMode ? '#1C1C1E' : '#FFFFFF',
    text: isDarkMode ? '#F5F5F5' : '#1C1C1E',
    textSecondary: isDarkMode ? '#8E8E93' : '#6E6E73',
    accent: '#6C5CE7',
    danger: '#FF3B30',
    success: '#34C759',
    border: isDarkMode ? '#2C2C2E' : '#E5E5EA',
    inputBg: isDarkMode ? '#2C2C2E' : '#F0F0F5',
  };

  const getDbPath = useCallback(() => {
    const baseDir =
      Platform.OS === 'ios'
        ? RNFS.LibraryDirectoryPath
        : RNFS.DocumentDirectoryPath;
    return `${baseDir}/secure_vault.db`;
  }, []);


  // On mount, try to unlock existing key
  useEffect(() => {
    const tryLoadExisting = async () => {
      try {
        const path = getDbPath();
        console.log('DB path:', JSON.stringify(path));

        const exists = await RNFS.exists(path);
        console.log('DB exists:', exists);

        if (!exists) {
          console.log('No database found, showing generate screen.');
          setState('no-key');
          return;
        }

        // Set credentials via sync method (strings arrive correctly)
        CryptoAtomicsKey.setCredentials('Sairaj', path);
        // Now unlock reads from globals, not the corrupted async params
        const key = await CryptoAtomicsKey.unlock_and_get_key('Sairaj', path);
        setPrivateKey(key);
        setState('ready');
      } catch (e: any) {
        console.log('Unlock failed:', e?.message);
        setState('no-key');
      }
    };
    tryLoadExisting();
  }, [getDbPath]);

  // Clean up interval on unmount
  useEffect(() => {
    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
    };
  }, []);

  const generateKey = useCallback(() => {
    setError('');
    setPrivateKey('');
    setSignature('');
    setState('generating');
    setProgress(0);

    const path = getDbPath();
    CryptoAtomicsKey.generateAndStore('Sairaj', path);

    intervalRef.current = setInterval(async () => {
      const p = CryptoAtomicsKey.getDerivationProgress();
      setProgress(p);

      if (p >= 100) {
        if (intervalRef.current) clearInterval(intervalRef.current);
        intervalRef.current = null;

        // Read key directly from memory — no decryption needed
        const keyHex = CryptoAtomicsKey.getActiveKeyHex();
        if (keyHex) {
          setPrivateKey(keyHex);
        } else {
          setError('Key generation completed but key is not accessible.');
        }
        setState('ready');
      }
    }, 100);
  }, [getDbPath]);

  const signMsg = useCallback(() => {
    setError('');
    setSignature('');
    if (!message.trim()) {
      setError('Please enter a message to sign.');
      return;
    }
    const hexMessage = message
      .split('')
      .map(c => c.charCodeAt(0).toString(16).padStart(2, '0'))
      .join('');
    const sig = CryptoAtomicsKey.signMessage(hexMessage);
    if (sig === 'ERROR_LOCKED') {
      setError('Vault is locked. Generate a key first.');
    } else {
      setSignature(sig);
    }
  }, [message]);

  const truncateKey = (key: string, chars = 14) => {
    if (key.length <= chars * 2) return key;
    return `${key.slice(0, chars)}...${key.slice(-chars)}`;
  };

  return (
    <View
      style={[
        styles.container,
        { backgroundColor: colors.bg, paddingTop: insets.top },
      ]}
    >
      <StatusBar barStyle={isDarkMode ? 'light-content' : 'dark-content'} />

      <ScrollView
        contentContainerStyle={[
          styles.scroll,
          { paddingBottom: insets.bottom + 24 },
        ]}
        showsVerticalScrollIndicator={false}
      >
        {/* Header */}
        <View style={styles.header}>
          <Text style={styles.headerIcon}>🔐</Text>
          <Text style={[styles.headerTitle, { color: colors.text }]}>
            Crypto Vault
          </Text>
          <Text
            style={[styles.headerSubtitle, { color: colors.textSecondary }]}
          >
            Secure key generation & signing
          </Text>
        </View>

        {/* Loading */}
        {state === 'loading' && (
          <View
            style={[
              styles.card,
              { backgroundColor: colors.card, borderColor: colors.border },
            ]}
          >
            <ActivityIndicator color={colors.accent} size="large" />
            <Text
              style={[
                styles.placeholderText,
                { color: colors.textSecondary, marginTop: 12 },
              ]}
            >
              Loading vault...
            </Text>
          </View>
        )}

        {/* No key — show generate button */}
        {state === 'no-key' && (
          <View
            style={[
              styles.card,
              { backgroundColor: colors.card, borderColor: colors.border },
            ]}
          >
            <View style={styles.cardHeader}>
              <View
                style={[
                  styles.statusDot,
                  { backgroundColor: colors.textSecondary },
                ]}
              />
              <Text style={[styles.cardTitle, { color: colors.textSecondary }]}>
                NO KEY FOUND
              </Text>
            </View>
            <Text
              style={[
                styles.placeholderText,
                {
                  color: colors.textSecondary,
                  textAlign: 'center',
                  marginBottom: 20,
                },
              ]}
            >
              Generate a new signing key to get started.
            </Text>
            <TouchableOpacity
              style={[
                styles.button,
                styles.primaryButton,
                { backgroundColor: colors.accent },
              ]}
              onPress={generateKey}
              activeOpacity={0.8}
            >
              <Text style={styles.buttonIcon}>⚡</Text>
              <Text style={styles.primaryButtonText}>Generate Key</Text>
            </TouchableOpacity>
          </View>
        )}

        {/* Generating */}
        {state === 'generating' && (
          <View
            style={[
              styles.card,
              { backgroundColor: colors.card, borderColor: colors.border },
            ]}
          >
            <View style={styles.cardHeader}>
              <ActivityIndicator color={colors.accent} size="small" />
              <Text
                style={[
                  styles.cardTitle,
                  { color: colors.textSecondary, marginLeft: 8 },
                ]}
              >
                GENERATING KEY
              </Text>
            </View>
            <Text
              style={[
                styles.placeholderText,
                { color: colors.textSecondary, marginBottom: 12 },
              ]}
            >
              Running Argon2 key derivation...
            </Text>
            <View style={styles.progressContainer}>
              <View
                style={[
                  styles.progressTrack,
                  { backgroundColor: colors.border },
                ]}
              >
                <View
                  style={[
                    styles.progressFill,
                    { width: `${progress}%`, backgroundColor: colors.accent },
                  ]}
                />
              </View>
              <Text
                style={[styles.progressText, { color: colors.textSecondary }]}
              >
                {Math.round(progress)}%
              </Text>
            </View>
          </View>
        )}

        {/* Ready — show key + sign message */}
        {state === 'ready' && (
          <>
            {/* Key Card */}
            <View
              style={[
                styles.card,
                { backgroundColor: colors.card, borderColor: colors.border },
              ]}
            >
              <View style={styles.cardHeader}>
                <View
                  style={[
                    styles.statusDot,
                    { backgroundColor: colors.success },
                  ]}
                />
                <Text
                  style={[styles.cardTitle, { color: colors.textSecondary }]}
                >
                  KEY ACTIVE
                </Text>
              </View>
              <Text style={[styles.keyLabel, { color: colors.textSecondary }]}>
                Private Key
              </Text>
              <Text
                style={[styles.keyValue, { color: colors.text }]}
                selectable
              >
                {truncateKey(privateKey)}
              </Text>

              {/* Regenerate */}
              <TouchableOpacity
                style={[styles.regenButton, { borderColor: colors.border }]}
                onPress={generateKey}
                activeOpacity={0.7}
              >
                <Text style={styles.regenIcon}>🔄</Text>
                <Text
                  style={[styles.regenText, { color: colors.textSecondary }]}
                >
                  Regenerate
                </Text>
              </TouchableOpacity>
            </View>

            {/* Sign Message Card */}
            <View
              style={[
                styles.card,
                { backgroundColor: colors.card, borderColor: colors.border },
              ]}
            >
              <View style={styles.cardHeader}>
                <Text style={{ fontSize: 14 }}>✍️</Text>
                <Text
                  style={[
                    styles.cardTitle,
                    { color: colors.textSecondary, marginLeft: 6 },
                  ]}
                >
                  SIGN MESSAGE
                </Text>
              </View>

              <TextInput
                style={[
                  styles.input,
                  {
                    backgroundColor: colors.inputBg,
                    color: colors.text,
                    borderColor: colors.border,
                  },
                ]}
                placeholder="Enter message to sign..."
                placeholderTextColor={colors.textSecondary}
                value={message}
                onChangeText={setMessage}
                multiline
              />

              <TouchableOpacity
                style={[
                  styles.button,
                  styles.primaryButton,
                  { backgroundColor: colors.accent, marginTop: 12 },
                ]}
                onPress={signMsg}
                activeOpacity={0.8}
              >
                <Text style={styles.buttonIcon}>🖊️</Text>
                <Text style={styles.primaryButtonText}>Sign</Text>
              </TouchableOpacity>

              {signature !== '' && (
                <View
                  style={[
                    styles.signatureBox,
                    {
                      backgroundColor: colors.inputBg,
                      borderColor: colors.border,
                    },
                  ]}
                >
                  <Text
                    style={[styles.keyLabel, { color: colors.textSecondary }]}
                  >
                    Signature
                  </Text>
                  <Text
                    style={[styles.signatureValue, { color: colors.text }]}
                    selectable
                  >
                    {signature}
                  </Text>
                </View>
              )}
            </View>
          </>
        )}

        {/* Error */}
        {error !== '' && (
          <View
            style={[
              styles.errorCard,
              {
                backgroundColor: `${colors.danger}15`,
                borderColor: colors.danger,
              },
            ]}
          >
            <Text style={[styles.errorText, { color: colors.danger }]}>
              {error}
            </Text>
          </View>
        )}

        {/* Footer */}
        <View style={styles.footer}>
          <Text style={[styles.footerText, { color: colors.textSecondary }]}>
            Powered by Argon2 + ChaCha20-Poly1305
          </Text>
        </View>
      </ScrollView>
    </View>
  );
}

function App() {
  return (
    <SafeAreaProvider style={StyleSheet.absoluteFill}>
      <AppContent />
    </SafeAreaProvider>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
  },
  scroll: {
    paddingHorizontal: 20,
  },
  header: {
    alignItems: 'center',
    marginTop: 32,
    marginBottom: 28,
  },
  headerIcon: {
    fontSize: 48,
    marginBottom: 12,
  },
  headerTitle: {
    fontSize: 28,
    fontWeight: '700',
    letterSpacing: -0.5,
  },
  headerSubtitle: {
    fontSize: 15,
    marginTop: 4,
  },
  card: {
    borderRadius: 16,
    padding: 20,
    borderWidth: 1,
    marginBottom: 16,
  },
  cardHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    marginBottom: 14,
  },
  statusDot: {
    width: 8,
    height: 8,
    borderRadius: 4,
    marginRight: 8,
  },
  cardTitle: {
    fontSize: 12,
    fontWeight: '600',
    letterSpacing: 1,
  },
  keyLabel: {
    fontSize: 12,
    fontWeight: '500',
    marginBottom: 4,
  },
  keyValue: {
    fontSize: 15,
    fontWeight: '600',
    fontFamily: Platform.OS === 'ios' ? 'Menlo' : 'monospace',
  },
  placeholderText: {
    fontSize: 15,
  },
  progressContainer: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 12,
  },
  progressTrack: {
    flex: 1,
    height: 6,
    borderRadius: 3,
    overflow: 'hidden',
  },
  progressFill: {
    height: '100%',
    borderRadius: 3,
  },
  progressText: {
    fontSize: 13,
    fontWeight: '600',
    fontFamily: Platform.OS === 'ios' ? 'Menlo' : 'monospace',
    width: 40,
    textAlign: 'right',
  },
  regenButton: {
    flexDirection: 'row',
    alignItems: 'center',
    alignSelf: 'flex-start',
    marginTop: 14,
    paddingVertical: 6,
    paddingHorizontal: 12,
    borderRadius: 8,
    borderWidth: 1,
    gap: 6,
  },
  regenIcon: {
    fontSize: 14,
  },
  regenText: {
    fontSize: 13,
    fontWeight: '500',
  },
  input: {
    borderRadius: 12,
    borderWidth: 1,
    padding: 14,
    fontSize: 15,
    minHeight: 80,
    textAlignVertical: 'top',
    fontFamily: Platform.OS === 'ios' ? 'Menlo' : 'monospace',
  },
  signatureBox: {
    marginTop: 14,
    padding: 14,
    borderRadius: 12,
    borderWidth: 1,
  },
  signatureValue: {
    fontSize: 13,
    fontWeight: '500',
    fontFamily: Platform.OS === 'ios' ? 'Menlo' : 'monospace',
    lineHeight: 20,
  },
  errorCard: {
    borderRadius: 12,
    padding: 14,
    borderWidth: 1,
    marginBottom: 16,
  },
  errorText: {
    fontSize: 14,
    fontWeight: '500',
  },
  actions: {
    gap: 12,
    marginTop: 8,
  },
  button: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    height: 52,
    borderRadius: 14,
    gap: 8,
  },
  primaryButton: {
    shadowColor: '#6C5CE7',
    shadowOffset: { width: 0, height: 4 },
    shadowOpacity: 0.3,
    shadowRadius: 8,
    elevation: 6,
  },
  primaryButtonText: {
    color: '#fff',
    fontSize: 16,
    fontWeight: '600',
  },
  buttonIcon: {
    fontSize: 18,
  },
  footer: {
    alignItems: 'center',
    marginTop: 16,
  },
  footerText: {
    fontSize: 12,
  },
});

export default App;
