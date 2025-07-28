// Mock Supabase client for demo purposes
export function createClient() {
  return {
    auth: {
      signInWithPassword: async ({ email, password }: { email: string; password: string }) => {
        // Demo credentials
        const validCredentials = [
          { email: "admin@pent.com", password: "admin123", role: "admin" },
          { email: "pentester@pent.com", password: "pent123", role: "pentester" },
          { email: "viewer@pent.com", password: "view123", role: "viewer" },
          { email: "guest@pent.com", password: "guest123", role: "guest" },
        ]

        const user = validCredentials.find((cred) => cred.email === email && cred.password === password)

        if (user) {
          return {
            data: {
              user: { id: "demo-user-id", email: user.email, role: user.role },
              session: { access_token: "demo-token" },
            },
            error: null,
          }
        } else {
          return {
            data: { user: null, session: null },
            error: { message: "Invalid login credentials" },
          }
        }
      },
      getUser: async () => {
        let isAuthenticated, userEmail, userRole;

        if (typeof window !== 'undefined') {
          const cookies = Object.fromEntries(
            document.cookie.split('; ').map(c => c.split('='))
          );
          isAuthenticated = cookies.isAuthenticated === 'true';
          userEmail = cookies.userEmail;
          userRole = cookies.userRole;
        } else {
          const headersModule = await import('next/headers') as typeof import('next/headers');
          const cookieStore = headersModule.cookies();
          isAuthenticated = cookieStore.get('isAuthenticated')?.value === 'true';
          userEmail = cookieStore.get('userEmail')?.value;
          userRole = cookieStore.get('userRole')?.value;
        }

        if (isAuthenticated && userEmail) {
          return {
            data: {
              user: { id: "demo-user-id", email: userEmail, role: userRole },
            },
            error: null,
          }
        } else {
          return {
            data: { user: null },
            error: null,
          }
        }
      },
      signOut: async () => {
        if (typeof window !== 'undefined') {
          document.cookie = 'isAuthenticated=; path=/; max-age=0';
          document.cookie = 'userEmail=; path=/; max-age=0';
          document.cookie = 'userRole=; path=/; max-age=0';
        }
        return { error: null }
      },
    },
    from: () => ({
      insert: () => ({ select: () => ({ single: () => ({ data: null }) }) }),
      select: () => ({ eq: () => ({ single: () => ({ data: null }) }) }),
      order: () => ({ limit: () => ({ data: [] }) }),
    }),
  }
}
