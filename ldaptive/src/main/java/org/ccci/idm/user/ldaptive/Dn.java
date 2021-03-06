package org.ccci.idm.user.ldaptive;

import com.google.common.base.MoreObjects;
import com.google.common.collect.ImmutableList;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.annotation.concurrent.Immutable;
import java.io.Serializable;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

@Immutable
public final class Dn implements Comparable<Dn>, Serializable {
    private static final long serialVersionUID = 5510344429904560934L;

    public static final Dn ROOT = new Dn();

    @Nonnull
    private final List<Component> components;

    public Dn(@Nonnull final Component... components) {
        this.components = ImmutableList.copyOf(components);
    }

    public Dn(@Nonnull final List<Component> components) {
        this.components = ImmutableList.copyOf(components);
    }

    @Nonnull
    public final List<Component> getComponents() {
        return components;
    }

    @Nullable
    public final String getName() {
        return components.isEmpty() ? null : components.get(components.size() - 1).value;
    }

    public final boolean isDescendantOf(@Nonnull final Dn ancestor) {
        return ancestor.components.size() < components.size() && isDescendantOfOrEqualTo(ancestor);
    }

    /**
     * @param ancestor the DN we are comparing to this DN.
     * @return true if the DN represented by this object is a descendant of or equal to the specified DN.
     */
    public final boolean isDescendantOfOrEqualTo(@Nonnull final Dn ancestor) {
        return ancestor.components.size() <= components.size() &&
                ancestor.components.equals(components.subList(0, ancestor.components.size()));
    }

    public final boolean isAncestorOf(@Nonnull final Dn descendant) {
        return descendant.isDescendantOf(this);
    }

    /**
     * @param descendant the DN we are comparing to this DN.
     * @return true if the DN represented by this object is an ancestor of or equal to the specified DN.
     */
    public final boolean isAncestorOfOrEqualTo(@Nonnull final Dn descendant) {
        return descendant.isDescendantOfOrEqualTo(this);
    }

    @Nonnull
    public final Dn descendant(@Nonnull final Component... components) {
        return new Dn(ImmutableList.<Component>builder().addAll(this.components).add(components).build());
    }

    @Nonnull
    public final Dn child(@Nonnull final String type, @Nonnull final String value) {
        return descendant(new Component(type, value));
    }

    @Nonnull
    public final LdapGroup asGroup() {
        return new LdapGroup(this);
    }

    @Nullable
    public final Dn parent() {
        if (!components.isEmpty()) {
            return new Dn(components.subList(0, components.size() - 1));
        }
        return null;
    }

    @Override
    public int compareTo(@Nonnull final Dn o) {
        int resp = 0;
        int i;
        for (i = 0; resp == 0 && i < components.size() && i < o.components.size(); i++) {
            resp = components.get(i).compareTo(o.components.get(i));
        }
        if (resp == 0) {
            resp = Integer.valueOf(components.size()).compareTo(o.components.size());
        }
        return resp;
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) { return true; }
        return o != null && getClass().equals(o.getClass()) && components.equals(((Dn) o).components);
    }

    @Override
    public int hashCode() {
        return components.hashCode();
    }

    @Override
    public String toString() {
        return MoreObjects.toStringHelper(this).add("components", components).toString();
    }

    @Immutable
    public static final class Component implements Comparable<Component>, Serializable {
        private static final long serialVersionUID = -5497975422744151635L;

        @Nonnull
        public final String type;
        @Nonnull
        public final String value;

        public Component(@Nonnull final String type, @Nonnull final String value) {
            this.type = type;
            this.value = value;
        }

        @Override
        public int compareTo(@Nonnull final Component o) {
            int resp = value.compareToIgnoreCase(o.value);
            if (resp == 0) {
                resp = type.compareToIgnoreCase(o.type);
            }
            return resp;
        }

        @Override
        public boolean equals(final Object o) {
            if (this == o) { return true; }
            if (!(o instanceof Component)) { return false; }
            final Component component = (Component) o;
            return type.equalsIgnoreCase(component.type) && value.equalsIgnoreCase(component.value);
        }

        @Override
        public int hashCode() {
            return Arrays.hashCode(new String[]{type.toLowerCase(Locale.US), value.toLowerCase(Locale.US)});
        }

        @Override
        public String toString() {
            return MoreObjects.toStringHelper(this).add("type", type).add("value", value).toString();
        }
    }
}
